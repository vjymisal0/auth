package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/badoux/checkmail"
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

type scimUserRepository struct {
	api *API
}

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
	var row *models.SCIMUser
	var created *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		row, created, terr = s.create(tx, change)
		return terr
	})
	if err != nil {
		return nil, scimError(err)
	}
	s.runAfterUserCreatedHook(r, db, created)
	return s.renderOne(db, providerID, row, protocol.Projection{})
}

func (s *scimUserRepository) Replace(ctx context.Context, user *core.User) (*core.User, error) {
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
	var row *models.SCIMUser
	var created *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		row, created, terr = s.replace(tx, change, existing)
		return terr
	})
	if err != nil {
		return nil, scimError(err)
	}
	s.runAfterUserCreatedHook(r, db, created)
	return s.renderOne(db, target.ProviderID, row, protocol.Projection{})
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
	memberships, err := models.FindSCIMGroupsForUsers(tx, providerID, ids)
	if err != nil {
		return nil, err
	}
	base := scimBaseURL(s.api.config)
	for _, m := range memberships {
		groups[m.SCIMUserID] = append(groups[m.SCIMUserID], core.GroupMembership{
			Value:   m.GroupID.String(),
			Ref:     base + "/Groups/" + m.GroupID.String(),
			Display: m.Display,
			Type:    "direct",
		})
	}
	return groups, nil
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
	if err := logoutSCIMLinkedUser(tx, row.UserID); err != nil {
		return err
	}
	if err := s.api.removeSCIMUserFromGroups(tx, r, scimActor(r), row); err != nil {
		return err
	}
	return s.audit(tx, r, models.SCIMUserDeletedAction, row)
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
	if err := lockSCIMLinkedUser(tx, old.UserID); err != nil {
		return nil, err
	}
	return old, nil
}

func (s *scimUserRepository) replaceRow(tx *storage.Connection, target models.SCIMTarget, old *models.SCIMUser, resource []byte) (*models.SCIMUser, bool, error) {
	if old.UserID != nil {
		unchanged, err := models.FindUnchangedSCIMUser(tx, target, resource)
		if err != nil || unchanged != nil {
			return unchanged, false, err
		}
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
		return nil, models.LogoutSCIMUser(tx, linked.ID)
	}
	return nil, nil
}

func (s *scimUserRepository) provisionAuthUser(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, error) {
	linked, isNew, err := s.linkAuthUser(tx, row, user)
	if err != nil {
		return nil, err
	}
	var created *models.User
	if isNew {
		created = linked
	}
	if !row.Active {
		return created, models.LogoutSCIMUser(tx, linked.ID)
	}
	return created, nil
}

func (s *scimUserRepository) linkAuthUser(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, bool, error) {
	providerType := scimProviderType(row.SSOProviderID)
	decision, err := s.decideAccountLinking(tx, providerType, user)
	if err != nil {
		return nil, false, err
	}

	linked := decision.User
	switch decision.Decision {
	case models.AccountExists:
		if err = scimCanLink(linked); err != nil {
			return nil, false, err
		}
	case models.LinkAccount:
		if err = scimCanLink(linked); err != nil {
			return nil, false, err
		}
		if _, err = s.api.createNewIdentity(tx, linked, providerType, scimIdentityData(user)); err != nil {
			return nil, false, err
		}
		if err = linked.UpdateAppMetaDataProviders(tx); err != nil {
			return nil, false, err
		}
	case models.CreateAccount:
		if linked, err = s.createAuthUser(tx, providerType, decision, user); err != nil {
			return nil, false, err
		}
		return linked, true, models.LinkSCIMUser(tx, row, linked.ID)
	case models.MultipleAccounts:
		return nil, false, scimerrors.ErrUniqueness("multiple users share this email in the SSO provider")
	default:
		return nil, false, apierrors.NewInternalServerError("Unknown automatic linking decision: %v", decision.Decision)
	}

	return linked, false, models.LinkSCIMUser(tx, row, linked.ID)
}

func scimCanLink(linked *models.User) error {
	if !linked.IsSSOUser {
		return scimerrors.ErrUniqueness("user is not an SSO user")
	}
	return nil
}

func (s *scimUserRepository) createAuthUser(tx *storage.Connection, providerType string, decision models.AccountLinkingResult, user *core.User) (*models.User, error) {
	candidate, err := s.newUser(providerType, decision, user)
	if err != nil {
		return nil, err
	}
	created, err := s.api.signupNewUser(tx, candidate)
	if err != nil {
		return nil, err
	}
	if _, err := s.api.createNewIdentity(tx, created, providerType, scimIdentityData(user)); err != nil {
		return nil, err
	}
	return created, nil
}

func (s *scimUserRepository) beforeProvision(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
	if scimUserEmail(user) == "" {
		return errSCIMEmailRequired()
	}
	return scimError(s.runBeforeUserCreatedHook(r, db, providerID, user))
}

func (s *scimUserRepository) runBeforeUserCreatedHook(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
	if !s.api.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}
	providerType := scimProviderType(providerID)
	decision, err := s.decideAccountLinking(db, providerType, user)
	if err != nil || decision.Decision != models.CreateAccount {
		return err
	}
	candidate, err := s.newUser(providerType, decision, user)
	if err != nil {
		return err
	}
	return scimHookError(s.api.triggerBeforeUserCreated(r, db, candidate))
}

func (s *scimUserRepository) runAfterUserCreatedHook(r *http.Request, db *storage.Connection, user *models.User) {
	if user == nil {
		return
	}
	if err := s.api.triggerAfterUserCreated(r, db, user); err != nil {
		observability.GetLogEntry(r).Entry.WithError(err).WithField("user_id", user.ID).Error("scim: after user created hook failed")
	}
}

func (s *scimUserRepository) decideAccountLinking(conn *storage.Connection, providerType string, user *core.User) (models.AccountLinkingResult, error) {
	emails := []provider.Email{{Email: scimUserEmail(user), Verified: true, Primary: true}}
	return models.DetermineAccountLinking(conn, s.api.config, emails, s.api.config.JWT.Aud, providerType, user.UserName)
}

func (s *scimUserRepository) newUser(providerType string, decision models.AccountLinkingResult, user *core.User) (*models.User, error) {
	params := &SignupParams{
		Provider: providerType,
		Email:    decision.CandidateEmail.Email,
		Aud:      s.api.config.JWT.Aud,
		Data:     scimIdentityData(user),
	}
	candidate, err := params.ToUserModel(true)
	if err != nil {
		return nil, err
	}
	now := s.api.Now()
	candidate.EmailConfirmedAt = &now
	return candidate, nil
}

func (s *scimUserRepository) renameIdentity(tx *storage.Connection, change scimUserChange, old *models.SCIMUser) error {
	providerID, user, userID := change.target.ProviderID, change.user, *old.UserID
	from, err := scimUserName(old.Resource)
	if err != nil || from == user.UserName {
		return err
	}
	data := map[string]any{"sub": user.UserName}
	if email := scimUserEmail(user); email != "" {
		data["email"] = email
	}
	err = models.RenameSCIMIdentity(tx, models.SCIMIdentityRename{
		UserID:   userID,
		Provider: scimProviderType(providerID),
		From:     from,
		To:       user.UserName,
		Data:     data,
	})
	if errors.Is(err, models.SCIMIdentityNotFoundError{}) {
		observability.GetLogEntry(change.r).Entry.WithField("user_id", userID).WithField("sso_provider_id", providerID).Warn("scim: SCIM identity not found, rename skipped")
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
	return linked.UpdateUserMetaData(tx, map[string]any{"email": email})
}

func (s *scimUserRepository) audit(tx *storage.Connection, r *http.Request, action models.AuditAction, row *models.SCIMUser) error {
	return s.api.auditSCIM(tx, r, scimActor(r), action, row.SSOProviderID, scimUserTraits(row))
}

func (a *API) deleteSCIMUsers(tx *storage.Connection, r *http.Request, actor *models.User, userID uuid.UUID) error {
	rows, err := models.SoftDeleteSCIMUsersByUserID(tx, userID)
	if err != nil {
		return err
	}
	for i := range rows {
		if err := a.removeSCIMUserFromGroups(tx, r, actor, &rows[i]); err != nil {
			return err
		}
		if err := a.auditSCIM(tx, r, actor, models.SCIMUserDeletedAction, rows[i].SSOProviderID, scimUserTraits(&rows[i])); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) removeSCIMUserFromGroups(tx *storage.Connection, r *http.Request, actor *models.User, row *models.SCIMUser) error {
	groupIDs, err := models.RemoveSCIMUserFromGroups(tx, row.ID)
	if err != nil {
		return err
	}
	for _, groupID := range groupIDs {
		if err := a.auditSCIM(tx, r, actor, models.SCIMGroupMemberRemovedAction, row.SSOProviderID, scimMemberTraits(groupID, row.ID, row.UserID)); err != nil {
			return err
		}
	}
	return nil
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
	return models.LogoutSCIMUser(tx, *userID)
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
		"sub":            user.UserName,
		"email":          scimUserEmail(user),
		"email_verified": true,
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

func scimHookError(err error) error {
	var httpErr *apierrors.HTTPError
	if errors.As(err, &httpErr) && httpErr.HTTPStatus < http.StatusInternalServerError {
		return scimerrors.NewError(httpErr.HTTPStatus, "", httpErr.Message)
	}
	return err
}
