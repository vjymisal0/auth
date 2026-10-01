package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/badoux/checkmail"
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

const (
	scimClaimSub           = "sub"
	scimClaimEmail         = "email"
	scimClaimEmailVerified = "email_verified"
)

type scimUserRepository struct {
	api *API
}

type scimUserWrite func(tx *storage.Connection, change scimUserChange) (*models.SCIMUser, *models.User, error)

type scimUserChange struct {
	r        *http.Request
	target   models.SCIMTarget
	resource []byte
	user     *core.User
}

func (s *scimUserRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	return scimLister[models.SCIMUser, *core.User]{
		schemas: scimUserSchemas,
		name:    "userName",
		find:    models.FindSCIMUsers,
		render:  s.render,
	}.list(ctx, s.api.db.WithContext(ctx), query)
}

func (s *scimUserRepository) Get(ctx context.Context, id string) (*core.User, error) {
	target, err := scimTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	row, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, scimError(err)
	}
	return s.renderOne(db, target.ProviderID, row, protocol.ProjectionFrom(ctx))
}

func (s *scimUserRepository) Create(ctx context.Context, user *core.User) (*core.User, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, err
	}
	resource, err := scimUserResource(user)
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	if err := s.beforeProvision(r, db, providerID, user); err != nil {
		return nil, err
	}

	change := scimUserChange{r: r, target: models.SCIMTarget{ProviderID: providerID}, resource: resource, user: user}
	return s.save(db, change, s.create)
}

func (s *scimUserRepository) Update(ctx context.Context, user *core.User) (*core.User, error) {
	target, err := scimTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return nil, err
	}
	resource, err := scimUserResource(user)
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, scimError(err)
	}
	if existing.UserID == nil {
		if err := s.beforeProvision(r, db, target.ProviderID, user); err != nil {
			return nil, err
		}
	}

	change := scimUserChange{r: r, target: target, resource: resource, user: user}
	return s.save(db, change, func(tx *storage.Connection, change scimUserChange) (*models.SCIMUser, *models.User, error) {
		return s.replace(tx, change, existing)
	})
}

func (s *scimUserRepository) Delete(ctx context.Context, id, version string) error {
	target, err := scimTarget(ctx, id, version)
	if err != nil {
		return err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	db := s.api.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return scimError(err)
	}
	return scimError(db.Transaction(func(tx *storage.Connection) error {
		return s.delete(tx, r, target, existing)
	}))
}

func (s *scimUserRepository) save(db *storage.Connection, change scimUserChange, write scimUserWrite) (*core.User, error) {
	var (
		saved   *core.User
		created *models.User
	)
	err := db.Transaction(func(tx *storage.Connection) error {
		row, user, terr := write(tx, change)
		if terr != nil {
			return terr
		}
		created = user
		saved, terr = s.renderOne(tx, change.target.ProviderID, row, scimSavedUserProjection(change))
		return terr
	})
	if err != nil {
		return nil, scimError(err)
	}
	s.runAfterUserCreatedHook(change.r, db, created)
	return saved, nil
}

func (s *scimUserRepository) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMUser, projection protocol.Projection) ([]*core.User, error) {
	groups, err := s.groupMemberships(tx, providerID, rows, projection)
	if err != nil {
		return nil, err
	}
	base := scimBaseURL(s.api.config)
	users := make([]*core.User, 0, len(rows))
	for _, row := range rows {
		user := &core.User{}
		if err := json.Unmarshal(row.Resource, user); err != nil {
			return nil, err
		}
		user.Active = &row.Active
		user.ID = row.ID.String()
		user.Schemas = []core.SchemaURI{core.SchemaUser}
		if user.EnterpriseUser != nil {
			user.Schemas = append(user.Schemas, core.SchemaEnterpriseUser)
		}
		user.Meta = scimMeta(scimResourceTypeUser, base+"/Users/"+user.ID, row.CreatedAt, row.UpdatedAt)
		user.Groups = groups[row.ID]
		users = append(users, user)
	}
	return users, nil
}

func (s *scimUserRepository) groupMemberships(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMUser, projection protocol.Projection) (map[uuid.UUID][]core.GroupMembership, error) {
	groups := map[uuid.UUID][]core.GroupMembership{}
	if !projection.Returns("groups") {
		return groups, nil
	}
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	memberships, err := models.FindSCIMMembershipsByUser(tx, providerID, ids)
	if err != nil {
		return nil, err
	}
	base := scimBaseURL(s.api.config)
	for _, m := range memberships {
		id := m.GroupID.String()
		groups[m.SCIMUserID] = append(groups[m.SCIMUserID], core.GroupMembership{
			Value:   id,
			Ref:     base + "/Groups/" + id,
			Display: m.Display,
			Type:    "direct",
		})
	}
	return groups, nil
}

func scimSavedUserProjection(change scimUserChange) protocol.Projection {
	if change.target.ID != uuid.Nil {
		return protocol.Projection{}
	}
	projection, err := protocol.ParseProjection(url.Values{"excludedAttributes": {"groups"}}, scimUserSchemas)
	if err != nil {
		return protocol.Projection{}
	}
	return projection
}

func (s *scimUserRepository) renderOne(tx *storage.Connection, providerID uuid.UUID, row *models.SCIMUser, projection protocol.Projection) (*core.User, error) {
	users, err := s.render(tx, providerID, []models.SCIMUser{*row}, projection)
	if err != nil {
		return nil, err
	}
	return users[0], nil
}

func (s *scimUserRepository) create(tx *storage.Connection, change scimUserChange) (*models.SCIMUser, *models.User, error) {
	if err := models.LockAccountLinking(tx, scimProviderType(change.target.ProviderID), scimUserEmail(change.user)); err != nil {
		return nil, nil, err
	}
	row, err := models.CreateSCIMUser(tx, change.target.ProviderID, change.resource)
	if err != nil {
		return nil, nil, err
	}
	created, err := s.provisionAuthUser(tx, row, change.user)
	if err != nil {
		return nil, nil, err
	}
	return row, created, s.audit(tx, change.r, models.SCIMUserCreatedAction, row)
}

func (s *scimUserRepository) replace(tx *storage.Connection, change scimUserChange, existing *models.SCIMUser) (*models.SCIMUser, *models.User, error) {
	old, err := s.lockForReplace(tx, change.target, scimUserEmail(change.user), existing)
	if err != nil {
		return nil, nil, err
	}
	row, changed, err := s.replaceRow(tx, change.target, old, change.resource)
	if err != nil || !changed {
		return row, nil, err
	}
	created, err := s.syncAuthUser(tx, change, old, row)
	if err != nil {
		return nil, nil, err
	}
	return row, created, s.audit(tx, change.r, scimUserAuditAction(old, row), row)
}

func (s *scimUserRepository) delete(tx *storage.Connection, r *http.Request, target models.SCIMTarget, existing *models.SCIMUser) error {
	if err := lockSCIMLinkedUser(tx, existing.UserID); err != nil {
		return err
	}
	row, err := models.DeleteSCIMUser(tx, target)
	if err != nil {
		return err
	}
	if !sameSCIMLink(row.UserID, existing.UserID) {
		return models.SCIMUserStaleError{}
	}
	if err := logoutSCIMLinkedUser(tx, row.UserID); err != nil {
		return err
	}
	events, err := scimUserRemovalEvents(tx, scimActor(r), row)
	if err != nil {
		return err
	}
	return s.api.auditSCIMEvents(tx, r, events)
}

func (s *scimUserRepository) lockForReplace(tx *storage.Connection, target models.SCIMTarget, email string, existing *models.SCIMUser) (*models.SCIMUser, error) {
	if err := models.LockAccountLinking(tx, scimProviderType(target.ProviderID), email); err != nil {
		return nil, err
	}
	if err := lockSCIMLinkedUser(tx, existing.UserID); err != nil {
		return nil, err
	}
	old, err := models.FindSCIMUserForUpdate(tx, target.ProviderID, target.ID)
	if err != nil {
		return nil, err
	}
	if !sameSCIMLink(old.UserID, existing.UserID) {
		return nil, models.SCIMUserStaleError{}
	}
	return old, nil
}

func sameSCIMLink(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (s *scimUserRepository) replaceRow(tx *storage.Connection, target models.SCIMTarget, old *models.SCIMUser, resource []byte) (*models.SCIMUser, bool, error) {
	if old.UserID != nil {
		return models.ReplaceSCIMUserIfChanged(tx, target, resource)
	}
	row, err := models.ReplaceSCIMUser(tx, target, resource)
	return row, err == nil, err
}

func (s *scimUserRepository) syncAuthUser(tx *storage.Connection, change scimUserChange, old, row *models.SCIMUser) (*models.User, error) {
	if old.UserID == nil {
		if scimUserEmail(change.user) == "" {
			return nil, errSCIMEmailRequired()
		}
		return s.provisionAuthUser(tx, row, change.user)
	}

	linked, err := models.FindUserByID(tx, *old.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.renameIdentity(tx, change, old); err != nil {
		return nil, err
	}
	if err := s.changeEmail(tx, change, linked); err != nil {
		return nil, err
	}
	if old.Active && !row.Active {
		return nil, models.LogoutUserForSCIM(tx, linked.ID)
	}
	return nil, nil
}

func (s *scimUserRepository) renameIdentity(tx *storage.Connection, change scimUserChange, old *models.SCIMUser) error {
	providerID, user, userID := change.target.ProviderID, change.user, *old.UserID
	from, err := scimUserName(old.Resource)
	if err != nil || from == user.UserName {
		return err
	}
	data := map[string]any{scimClaimSub: user.UserName}
	if email := scimUserEmail(user); email != "" {
		data[scimClaimEmail] = email
	}
	err = models.RenameSCIMIdentity(tx, models.SCIMIdentityRename{
		UserID:   userID,
		Provider: scimProviderType(providerID),
		From:     from,
		To:       user.UserName,
		Data:     data,
	})
	if errors.Is(err, models.SCIMIdentityNotFoundError{}) {
		observability.GetLogEntry(change.r).Entry.WithField("user_id", userID).WithField("sso_provider_id", providerID).Warn("scim: identity not found, rename skipped")
		return nil
	}
	return err
}

func (s *scimUserRepository) changeEmail(tx *storage.Connection, change scimUserChange, linked *models.User) error {
	email := scimUserEmail(change.user)
	if email == "" || strings.EqualFold(email, linked.GetEmail()) {
		return nil
	}
	if err := models.ChangeSCIMIdentityEmail(tx, models.SCIMIdentityEmailChange{
		UserID:   linked.ID,
		Provider: scimProviderType(change.target.ProviderID),
		Subject:  change.user.UserName,
		Email:    email,
	}); err != nil {
		return err
	}
	if err := linked.SetEmail(tx, strings.ToLower(email)); err != nil {
		return err
	}
	if err := linked.ClearAllPendingTokens(tx); err != nil {
		return err
	}
	return linked.UpdateUserMetaData(tx, map[string]any{scimClaimEmail: email})
}

func (s *scimUserRepository) audit(tx *storage.Connection, r *http.Request, action models.AuditAction, row *models.SCIMUser) error {
	return s.api.auditSCIM(tx, r, scimAuditEvent{
		actor:      scimActor(r),
		action:     action,
		providerID: row.SSOProviderID,
		traits:     scimUserTraits(row),
	})
}

func scimUserResource(user *core.User) ([]byte, error) {
	resource, err := scimEncode(user, "id", "meta", "password", "groups")
	if err != nil {
		return nil, err
	}
	if err := scimValidatePrimaryEmail(user); err != nil {
		return nil, err
	}
	return resource, nil
}

func lockSCIMLinkedUser(tx *storage.Connection, userID *uuid.UUID) error {
	if userID == nil {
		return nil
	}
	return models.LockUserForSCIM(tx, *userID)
}

func logoutSCIMLinkedUser(tx *storage.Connection, userID *uuid.UUID) error {
	if userID == nil {
		return nil
	}
	return models.LogoutUserForSCIM(tx, *userID)
}

func scimUserEmail(user *core.User) string {
	if email := scimPrimaryEmail(user.Emails); email != "" {
		return email
	}
	if isEmailAddress(user.UserName) {
		return user.UserName
	}
	return ""
}

func scimValidatePrimaryEmail(user *core.User) error {
	if email := scimPrimaryEmail(user.Emails); email != "" && !isEmailAddress(email) {
		return errSCIMEmailInvalid()
	}
	return nil
}

func isEmailAddress(value string) bool {
	return len(value) <= 255 && checkmail.ValidateFormat(value) == nil
}

func scimPrimaryEmail(emails []core.Email) string {
	for _, email := range emails {
		if email.Primary != nil && *email.Primary {
			return email.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}

func scimIdentityData(user *core.User) map[string]any {
	return map[string]any{
		scimClaimSub:           user.UserName,
		scimClaimEmail:         scimUserEmail(user),
		scimClaimEmailVerified: true,
	}
}

func scimUserName(resource []byte) (string, error) {
	var r struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(resource, &r); err != nil {
		return "", err
	}
	return r.UserName, nil
}

func scimUserTraits(row *models.SCIMUser) map[string]any {
	traits := map[string]any{
		"scim_user_id": row.ID,
		"user_name":    row.UserName,
		"active":       row.Active,
	}
	if row.UserID != nil {
		traits["user_id"] = *row.UserID
	}
	return traits
}

func scimUserAuditAction(before, after *models.SCIMUser) models.AuditAction {
	switch {
	case before.Active && !after.Active:
		return models.SCIMUserDeactivatedAction
	case !before.Active && after.Active:
		return models.SCIMUserReactivatedAction
	}
	return models.SCIMUserUpdatedAction
}
