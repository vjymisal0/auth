package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const scimProviderDeletedBan = 100 * 365 * 24 * time.Hour

type AdminSCIMTokenCreateParams struct {
	ExpiresAt *time.Time `json:"expires_at"`
}

type AdminSCIMTokenCreateResponse struct {
	BaseURL string `json:"base_url"`
	Token   string `json:"token"`
	*models.SCIMToken
}

type AdminSCIMTokenListResponse struct {
	Tokens []models.SCIMToken `json:"tokens"`
}

type AdminSCIMStatusResponse struct {
	Enabled bool               `json:"enabled"`
	BaseURL string             `json:"base_url"`
	Tokens  []models.SCIMToken `json:"tokens"`
}

func (a *API) adminSCIMGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	return a.sendSCIMStatus(w, a.db.WithContext(ctx), getSSOProvider(ctx))
}

func (a *API) adminSCIMEnable(w http.ResponseWriter, r *http.Request) error {
	return a.changeSCIMEnabled(w, r, models.EnableSCIM, models.SCIMEnabledAction, "enabling")
}

func (a *API) adminSCIMDisable(w http.ResponseWriter, r *http.Request) error {
	return a.changeSCIMEnabled(w, r, models.DisableSCIM, models.SCIMDisabledAction, "disabling")
}

func (a *API) changeSCIMEnabled(w http.ResponseWriter, r *http.Request, change func(*storage.Connection, uuid.UUID) (bool, error), action models.AuditAction, verb string) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	if err := db.Transaction(func(tx *storage.Connection) error {
		changed, err := change(tx, provider.ID)
		if err != nil || !changed {
			return err
		}
		return a.auditSCIM(tx, r, getAdminUser(ctx), action, provider.ID, map[string]any{})
	}); err != nil {
		return apierrors.NewInternalServerError("Error %s SCIM", verb).WithInternalError(err)
	}

	return a.sendSCIMStatus(w, db, provider)
}

func (a *API) sendSCIMStatus(w http.ResponseWriter, db *storage.Connection, provider *models.SSOProvider) error {
	tokens, err := models.FindActiveSCIMTokensBySSOProvider(db, provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error finding SCIM tokens").WithInternalError(err)
	}
	enabled, err := a.isSCIMEnabled(db, provider)
	if err != nil {
		return apierrors.NewInternalServerError("Error finding SCIM settings").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMStatusResponse{
		Enabled: enabled,
		BaseURL: scimBaseURL(a.config),
		Tokens:  tokens,
	})
}

func (a *API) isSCIMEnabled(db *storage.Connection, provider *models.SSOProvider) (bool, error) {
	if !a.config.SSO.SCIM.Enabled || !provider.IsEnabled() {
		return false, nil
	}
	return models.IsSCIMEnabled(db, provider.ID)
}

func (a *API) deprovisionSCIM(tx *storage.Connection, r *http.Request, provider *models.SSOProvider) error {
	disabled, err := models.DisableSCIM(tx, provider.ID)
	if err != nil {
		return err
	}
	prefixes, err := a.revokeSCIMTokens(tx, r, provider)
	if err != nil {
		return err
	}
	if disabled && a.config.SSO.SCIM.Enabled {
		if err := a.auditSCIM(tx, r, getAdminUser(r.Context()), models.SCIMDisabledAction, provider.ID, map[string]any{"token_prefixes": prefixes}); err != nil {
			return err
		}
	}
	banned, err := models.BanDeprovisionedSCIMUsers(tx, provider.ID, a.Now().Add(scimProviderDeletedBan))
	if err != nil || banned == 0 {
		return err
	}
	return a.auditSCIM(tx, r, getAdminUser(r.Context()), models.SCIMUsersBannedAction, provider.ID, map[string]any{"banned_user_count": banned})
}

func (a *API) revokeSCIMTokens(tx *storage.Connection, r *http.Request, provider *models.SSOProvider) ([]string, error) {
	if err := models.LockSCIMTokens(tx, provider.ID); err != nil {
		return nil, err
	}
	tokens, err := models.RevokeSCIMTokensBySSOProvider(tx, provider.ID)
	if err != nil {
		return nil, err
	}
	actor := getAdminUser(r.Context())
	prefixes := make([]string, len(tokens))
	for i := range tokens {
		prefixes[i] = tokens[i].Prefix
		if err := a.auditSCIM(tx, r, actor, models.SCIMTokenRevokedAction, provider.ID, map[string]any{"token_prefix": tokens[i].Prefix}); err != nil {
			return nil, err
		}
	}
	return prefixes, nil
}

func (a *API) adminSCIMTokensCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	params := &AdminSCIMTokenCreateParams{}
	if body, err := utilities.GetBodyBytes(r); err != nil || len(body) > 0 {
		if err := retrieveRequestParams(r, params); err != nil {
			return err
		}
	}
	if params.ExpiresAt != nil && !params.ExpiresAt.After(a.Now()) {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "expires_at must be in the future")
	}

	var (
		token     *models.SCIMToken
		plaintext string
	)
	if err := db.Transaction(func(tx *storage.Connection) error {
		if err := models.LockSCIMTokens(tx, provider.ID); err != nil {
			return err
		}
		var err error
		if token, plaintext, err = models.CreateSCIMToken(tx, provider, params.ExpiresAt); err != nil {
			return err
		}
		return a.auditSCIM(tx, r, getAdminUser(ctx), models.SCIMTokenCreatedAction, provider.ID, map[string]any{"token_prefix": token.Prefix})
	}); err != nil {
		if errors.Is(err, models.SCIMTokenExpiryError{}) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "expires_at must be in the future")
		}
		return apierrors.NewInternalServerError("Error creating SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusCreated, &AdminSCIMTokenCreateResponse{
		BaseURL:   scimBaseURL(a.config),
		Token:     plaintext,
		SCIMToken: token,
	})
}

func (a *API) adminSCIMTokensList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	provider := getSSOProvider(ctx)

	tokens, err := models.FindSCIMTokensBySSOProvider(a.db.WithContext(ctx), provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error listing SCIM tokens").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &AdminSCIMTokenListResponse{Tokens: tokens})
}

func (a *API) adminSCIMTokensRevoke(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	var token *models.SCIMToken
	if err := db.Transaction(func(tx *storage.Connection) error {
		if err := models.LockSCIMTokens(tx, provider.ID); err != nil {
			return err
		}
		var err error
		if token, err = models.FindSCIMTokenByPrefix(tx, provider.ID, chi.URLParam(r, "prefix")); err != nil {
			return err
		}
		if token.IsRevoked() {
			return nil
		}
		if err = token.Revoke(tx); err != nil {
			return err
		}
		return a.auditSCIM(tx, r, getAdminUser(ctx), models.SCIMTokenRevokedAction, provider.ID, map[string]any{"token_prefix": token.Prefix})
	}); err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMTokenNotFound, "SCIM token not found")
		}
		return apierrors.NewInternalServerError("Error revoking SCIM token").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, token)
}
