package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/badoux/checkmail"
	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type scimUsers struct {
	api *API
}

func (s *scimUsers) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := scimSearch(query, scimUserSchemas, "userName")
	if err != nil {
		return nil, 0, err
	}
	db := s.api.db.WithContext(ctx)
	rows, total, err := models.FindSCIMUsers(db, providerID, search)
	if err != nil {
		return nil, 0, err
	}
	users, err := s.render(db, providerID, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (s *scimUsers) Get(ctx context.Context, id string) (*core.User, error) {
	providerID, resourceID, _, err := scimTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	row, err := models.FindSCIMUser(db, providerID, resourceID)
	if err != nil {
		return nil, scimTranslate(err)
	}
	return s.renderOne(db, providerID, row, protocol.ProjectionFrom(ctx))
}

func (s *scimUsers) Create(ctx context.Context, user *core.User) (*core.User, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, err
	}
	resource, err := scimUserResource(user)
	if err != nil {
		return nil, err
	}
	if err := scimValidateEmails(user); err != nil {
		return nil, err
	}
	if scimEmail(user) == "" {
		return nil, errSCIMEmailRequired()
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	if err := s.beforeCreate(r, db, providerID, user); err != nil {
		return nil, scimTranslate(err)
	}

	var row *models.SCIMUser
	var created *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.LockAccountLinking(tx, "sso:"+providerID.String(), scimEmail(user)); terr != nil {
			return terr
		}
		var terr error
		if row, terr = models.CreateSCIMUser(tx, providerID, resource); terr != nil {
			return terr
		}
		if created, terr = s.linkNew(tx, row, user); terr != nil {
			return terr
		}
		return s.audit(tx, r, models.SCIMUserCreatedAction, row)
	})
	if err != nil {
		return nil, scimTranslate(err)
	}
	s.afterCreate(r, db, created)
	return s.renderOne(db, providerID, row, protocol.Projection{})
}

func (s *scimUsers) Replace(ctx context.Context, user *core.User) (*core.User, error) {
	providerID, id, updatedAt, err := scimTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return nil, err
	}
	resource, err := scimUserResource(user)
	if err != nil {
		return nil, err
	}
	if err := scimValidateEmails(user); err != nil {
		return nil, err
	}
	email := scimEmail(user)
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, providerID, id)
	if err != nil {
		return nil, scimTranslate(err)
	}
	if existing.UserID == nil {
		if email == "" {
			return nil, errSCIMEmailRequired()
		}
		if err := s.beforeCreate(r, db, providerID, user); err != nil {
			return nil, scimTranslate(err)
		}
	}

	var row *models.SCIMUser
	var created *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.LockAccountLinking(tx, "sso:"+providerID.String(), email); terr != nil {
			return terr
		}
		if existing.UserID != nil {
			if terr := models.LockUserForSCIM(tx, *existing.UserID); terr != nil {
				return terr
			}
		}
		old, terr := models.FindSCIMUserForUpdate(tx, providerID, id)
		if terr != nil {
			return terr
		}
		if old.UserID != nil {
			if terr := models.LockUserForSCIM(tx, *old.UserID); terr != nil {
				return terr
			}
			if row, terr = models.FindUnchangedSCIMUser(tx, providerID, id, resource, updatedAt); terr != nil || row != nil {
				return terr
			}
		}
		if row, terr = models.ReplaceSCIMUser(tx, providerID, id, resource, updatedAt); terr != nil {
			return terr
		}
		if created, terr = s.sync(tx, providerID, old, row, user); terr != nil {
			return terr
		}
		return s.audit(tx, r, scimUserAuditAction(old, row), row)
	})
	if err != nil {
		return nil, scimTranslate(err)
	}
	s.afterCreate(r, db, created)
	return s.renderOne(db, providerID, row, protocol.Projection{})
}

func (s *scimUsers) Delete(ctx context.Context, id, version string) error {
	providerID, resourceID, updatedAt, err := scimTarget(ctx, id, version)
	if err != nil {
		return err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	db := s.api.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, providerID, resourceID)
	if err != nil {
		return scimTranslate(err)
	}
	return scimTranslate(db.Transaction(func(tx *storage.Connection) error {
		if existing.UserID != nil {
			if err := models.LockUserForSCIM(tx, *existing.UserID); err != nil {
				return err
			}
		}
		row, err := models.DeleteSCIMUser(tx, providerID, resourceID, updatedAt)
		if err != nil {
			return err
		}
		if row.UserID != nil {
			if err := scimDeactivate(tx, *row.UserID); err != nil {
				return err
			}
		}
		if err := s.api.removeSCIMUserFromGroups(tx, r, scimActor(r), row); err != nil {
			return err
		}
		return s.audit(tx, r, models.SCIMUserDeletedAction, row)
	}))
}

func (s *scimUsers) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMUser, projection protocol.Projection) ([]*core.User, error) {
	memberships := []models.SCIMGroupMembership{}
	if projection.Returns("groups") {
		ids := make([]uuid.UUID, len(rows))
		for i, row := range rows {
			ids[i] = row.ID
		}
		var err error
		if memberships, err = models.FindSCIMGroupsForUsers(tx, providerID, ids); err != nil {
			return nil, err
		}
	}
	base := scimBaseURL(s.api.config)
	groups := map[uuid.UUID][]core.GroupMembership{}
	for _, m := range memberships {
		groups[m.SCIMUserID] = append(groups[m.SCIMUserID], core.GroupMembership{
			Value:   m.GroupID.String(),
			Ref:     base + "/Groups/" + m.GroupID.String(),
			Display: m.Display,
			Type:    "direct",
		})
	}

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

func (s *scimUsers) renderOne(tx *storage.Connection, providerID uuid.UUID, row *models.SCIMUser, projection protocol.Projection) (*core.User, error) {
	users, err := s.render(tx, providerID, []models.SCIMUser{*row}, projection)
	if err != nil {
		return nil, err
	}
	return users[0], nil
}

func (s *scimUsers) sync(tx *storage.Connection, providerID uuid.UUID, old, row *models.SCIMUser, user *core.User) (*models.User, error) {
	if old.UserID == nil {
		if scimEmail(user) == "" {
			return nil, errSCIMEmailRequired()
		}
		return s.linkNew(tx, row, user)
	}

	linked, err := models.FindUserByID(tx, *old.UserID)
	if err != nil {
		return nil, err
	}
	if from := scimUserName(old.Resource); from != user.UserName {
		data := map[string]any{"sub": user.UserName}
		if email := scimEmail(user); email != "" {
			data["email"] = email
		}
		err := models.RenameSCIMIdentity(tx, linked.ID, "sso:"+providerID.String(), from, user.UserName, data)
		if errors.Is(err, models.SCIMIdentityNotFoundError{}) {
			logrus.WithField("user_id", linked.ID).WithField("sso_provider_id", providerID).Warn("scim: SCIM identity not found, rename skipped")
		} else if err != nil {
			return nil, err
		}
	}
	if old.Active && !row.Active {
		return nil, scimDeactivate(tx, linked.ID)
	}
	return nil, nil
}

func (s *scimUsers) linkNew(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, error) {
	linked, isNew, err := s.link(tx, row, user)
	if err != nil {
		return nil, err
	}
	var created *models.User
	if isNew {
		created = linked
	}
	if !row.Active {
		return created, scimDeactivate(tx, linked.ID)
	}
	return created, nil
}

func (s *scimUsers) link(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, bool, error) {
	providerType := "sso:" + row.SSOProviderID.String()
	decision, err := s.decide(tx, providerType, user)
	if err != nil {
		return nil, false, err
	}

	linked := decision.User
	switch decision.Decision {
	case models.AccountExists:
	case models.LinkAccount:
		if _, err = s.api.createNewIdentity(tx, linked, providerType, scimIdentityData(user)); err != nil {
			return nil, false, err
		}
		if err = linked.UpdateAppMetaDataProviders(tx); err != nil {
			return nil, false, err
		}
	case models.CreateAccount:
		if linked, err = s.newUser(providerType, decision, user); err != nil {
			return nil, false, err
		}
		if linked, err = s.api.signupNewUser(tx, linked); err != nil {
			return nil, false, err
		}
		if _, err = s.api.createNewIdentity(tx, linked, providerType, scimIdentityData(user)); err != nil {
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

func (s *scimUsers) beforeCreate(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
	if !s.api.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}
	providerType := "sso:" + providerID.String()
	decision, err := s.decide(db, providerType, user)
	if err != nil || decision.Decision != models.CreateAccount {
		return err
	}
	candidate, err := s.newUser(providerType, decision, user)
	if err != nil {
		return err
	}
	return scimHookError(s.api.triggerBeforeUserCreated(r, db, candidate))
}

func (s *scimUsers) afterCreate(r *http.Request, db *storage.Connection, user *models.User) {
	if user == nil {
		return
	}
	if err := s.api.triggerAfterUserCreated(r, db, user); err != nil {
		logrus.WithError(err).WithField("user_id", user.ID).Error("scim: after user created hook failed")
	}
}

func (s *scimUsers) decide(conn *storage.Connection, providerType string, user *core.User) (models.AccountLinkingResult, error) {
	emails := []provider.Email{{Email: scimEmail(user), Verified: true, Primary: true}}
	return models.DetermineAccountLinking(conn, s.api.config, emails, s.api.config.JWT.Aud, providerType, user.UserName)
}

func (s *scimUsers) newUser(providerType string, decision models.AccountLinkingResult, user *core.User) (*models.User, error) {
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
	now := time.Now()
	candidate.EmailConfirmedAt = &now
	return candidate, nil
}

func (s *scimUsers) audit(tx *storage.Connection, r *http.Request, action models.AuditAction, row *models.SCIMUser) error {
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
		if err := a.auditSCIMMember(tx, r, actor, models.SCIMGroupMemberRemovedAction, row.SSOProviderID, groupID, row.ID, row.UserID); err != nil {
			return err
		}
	}
	return nil
}

func scimUserResource(user *core.User) ([]byte, error) {
	return scimEncode(user, "id", "meta", "password", "groups")
}

func scimEmail(user *core.User) string {
	if email := scimPrimaryEmail(user.Emails); email != "" {
		return email
	}
	if isEmailAddress(user.UserName) {
		return user.UserName
	}
	return ""
}

func scimValidateEmails(user *core.User) error {
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
		"email":          scimEmail(user),
		"email_verified": true,
	}
}

func scimUserName(resource []byte) string {
	var r struct {
		UserName string `json:"userName"`
	}
	_ = json.Unmarshal(resource, &r)
	return r.UserName
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

func scimDeactivate(tx *storage.Connection, userID uuid.UUID) error {
	if err := models.LockUserForSCIM(tx, userID); err != nil {
		return err
	}
	return models.Logout(tx, userID)
}

func scimHookError(err error) error {
	var httpErr *apierrors.HTTPError
	if errors.As(err, &httpErr) && httpErr.HTTPStatus < http.StatusInternalServerError {
		return scimerrors.NewError(httpErr.HTTPStatus, "", httpErr.Message)
	}
	return err
}
