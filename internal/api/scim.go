package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const (
	scimBasePath          = "/scim/v2"
	scimResourceTypeUser  = "User"
	scimResourceTypeGroup = "Group"
)

var errMissingSSOProvider = errors.New("scim: request has no SSO provider")

func (a *API) newSCIMServer(validate server.TokenValidator, limit func(http.Handler) http.Handler) *server.Server {
	requireToken := server.RequireBearerToken(validate)
	authenticate := func(next http.Handler) http.Handler {
		if limit != nil {
			next = limit(next)
		}
		return requireToken(next)
	}
	return server.New(scimBasePath,
		core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting().Versioning(),
		server.WithBaseURL(scimBaseURL(a.config)),
		server.ErrorHandler(scimLogError),
		server.WithResource(server.NewResource[*core.User](scimResourceTypeUser, "/Users", core.SchemaUser, scimUserSchemas.Base().Attributes...).
			WithExtension(core.SchemaEnterpriseUser, scimUserSchemas.Extensions()[0].Attributes...).
			WithRepository(&scimUserRepository{api: a})),
		server.WithResource(server.NewResource[*core.Group](scimResourceTypeGroup, "/Groups", core.SchemaGroup, scimGroupSchemas.Base().Attributes...).
			WithRepository(&scimGroupRepository{api: a})),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), authenticate),
	)
}

var (
	scimUserSchemas = core.Schemas{
		core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
		core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
	}
	scimGroupSchemas = newSCIMGroupSchemas()
)

func newSCIMGroupSchemas() core.Schemas {
	attributes := core.GroupAttributes()
	for _, attribute := range attributes {
		for _, sub := range attribute.SubAttributes {
			switch sub.Name {
			case "type":
				sub.Suggesting(scimResourceTypeUser)
			case "$ref":
				sub.Referencing(scimResourceTypeUser)
			}
		}
	}
	return core.Schemas{core.NewSchema(core.SchemaGroup).With(attributes...)}
}

func scimBaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + scimBasePath
}

func scimTooManyRequests(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, errSCIMTooManyRequests())
}

func scimLogError(r *http.Request, err error) {
	observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
}

func newSCIMTokenValidator(db *storage.Connection) server.TokenValidator {
	return func(ctx context.Context, candidate string) (context.Context, error) {
		token, err := models.AuthenticateSCIMToken(db.WithContext(ctx), candidate)
		if models.IsNotFoundError(err) {
			return ctx, server.ErrInvalidToken
		}
		if err != nil {
			return ctx, err
		}
		return scimTokenKey.WithValue(ctx, token), nil
	}
}

func (a *API) withSCIMRequest(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	return scimRequestKey.WithValue(req.Context(), req), nil
}

func (a *API) limitSCIMByIP(lmt *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a.scimSkipsTokenValidator(r) && a.performRateLimiting(lmt, r) != nil {
				handler(scimTooManyRequests)(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *API) scimSkipsTokenValidator(r *http.Request) bool {
	if _, err := a.extractBearerToken(r); err != nil {
		return true
	}
	return r.URL.Path == scimBasePath+"/ServiceProviderConfig" || path.Clean(r.URL.Path) != r.URL.Path
}

func (a *API) limitSCIMInvalidToken(validate server.TokenValidator, lmt *limiter.Limiter) server.TokenValidator {
	return func(ctx context.Context, candidate string) (context.Context, error) {
		next, err := validate(ctx, candidate)
		if !errors.Is(err, server.ErrInvalidToken) {
			return next, err
		}
		if r := scimRequestKey.Value(ctx); r != nil && a.performRateLimiting(lmt, r) != nil {
			return ctx, errSCIMTooManyRequests()
		}
		return next, err
	}
}

func (a *API) limitSCIMByProvider(lmt *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if providerID, err := scimProviderID(r.Context()); err == nil && tollbooth.LimitByKeys(lmt, []string{providerID.String()}) != nil {
				handler(scimTooManyRequests)(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func scimSearch(query *protocol.SearchRequest, schemas core.Schemas, name string) (models.SCIMQuery, error) {
	search := models.SCIMQuery{Offset: query.Offset(), Limit: query.Count}
	if query.Filter != "" {
		criteria, err := protocol.Filter(schemas, query.Filter, scimEqFilter{name: name})
		if err != nil {
			return search, err
		}
		search.Filter = criteria
	}
	if query.SortBy == "" {
		return search, nil
	}
	parent, attribute, err := query.SortAttribute(schemas)
	if err != nil {
		return search, err
	}
	key := parent.Name
	if attribute != parent {
		key += "." + attribute.Name
	}
	by, ok := map[string]models.SCIMSortKey{
		"id":                  models.SCIMSortByID,
		strings.ToLower(name): models.SCIMSortByName,
		"meta.created":        models.SCIMSortByCreatedAt,
		"meta.lastmodified":   models.SCIMSortByUpdatedAt,
	}[strings.ToLower(key)]
	if !ok {
		return search, scimerrors.ErrInvalidValue(fmt.Sprintf(`"sortBy" must be one of "id", %q, "meta.created" or "meta.lastModified"`, name))
	}
	search.Order = models.SCIMOrder{By: by, Descending: query.Descending()}
	return search, nil
}

func scimEncode(resource core.Resource, drop ...string) ([]byte, error) {
	fields, err := core.NewObject(resource)
	if err != nil {
		return nil, err
	}
	for _, key := range drop {
		fields.Remove(key)
	}
	return json.Marshal(fields)
}

func scimTarget(ctx context.Context, id, version string) (providerID, resourceID uuid.UUID, updatedAt *time.Time, err error) {
	if providerID, err = scimProviderID(ctx); err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	if resourceID, err = uuid.FromString(id); err != nil {
		return uuid.Nil, uuid.Nil, nil, errSCIMNotFound()
	}
	if updatedAt, err = scimParseVersion(version); err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	return providerID, resourceID, updatedAt, nil
}

func scimProviderID(ctx context.Context) (uuid.UUID, error) {
	token := scimTokenKey.Value(ctx)
	if token == nil || token.SSOProviderID == uuid.Nil {
		return uuid.Nil, errMissingSSOProvider
	}
	return token.SSOProviderID, nil
}

func scimRequest(ctx context.Context) (*http.Request, error) {
	r := scimRequestKey.Value(ctx)
	if r == nil {
		return nil, apierrors.NewInternalServerError("SCIM request missing from context")
	}
	return r.WithContext(ctx), nil
}

func scimMeta(resourceType core.ResourceTypeName, location string, created, updated time.Time) core.Meta {
	return core.Meta{
		ResourceType: resourceType,
		Created:      created.UTC(),
		LastModified: updated.UTC(),
		Location:     location,
		Version:      scimVersion(updated),
	}
}

func scimVersion(updatedAt time.Time) string {
	return `W/"` + strconv.FormatInt(updatedAt.UnixMicro(), 10) + `"`
}

func scimParseVersion(version string) (*time.Time, error) {
	if version == "" {
		return nil, nil
	}
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil {
		return nil, errSCIMStale()
	}
	updatedAt := time.UnixMicro(micros)
	return &updatedAt, nil
}

func scimError(err error) error {
	switch {
	case models.IsNotFoundError(err):
		return errSCIMNotFound()
	case errors.Is(err, models.SCIMUserStaleError{}), errors.Is(err, models.SCIMGroupStaleError{}):
		return errSCIMStale()
	case errors.Is(err, models.SCIMGroupConflictError{}):
		return scimerrors.ErrUniqueness(`"externalId" must be unique`)
	case errors.As(err, &models.SCIMGroupMemberNotFoundError{}):
		return errSCIMMemberNotFound()
	case errors.Is(err, models.SCIMUserConflictError{}):
		return scimerrors.ErrUniqueness(`"userName" and "externalId" must be unique`)
	case errors.Is(err, models.SCIMUserLinkedError{}):
		return scimerrors.ErrUniqueness("user is already provisioned by this provider")
	}
	return err
}

func errSCIMNotFound() error {
	return scimerrors.ErrNotFound("Resource not found")
}

func errSCIMStale() error {
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func errSCIMMemberNotFound() error {
	return scimerrors.ErrInvalidValue(`"members.value" must reference a User in this provider`)
}

func errSCIMEmailRequired() error {
	return scimerrors.ErrInvalidValue(`"emails" or an email address "userName" is required`)
}

func errSCIMEmailInvalid() error {
	return scimerrors.ErrInvalidValue(`"emails" value must be an email address`)
}

func errSCIMTooManyRequests() error {
	return scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached")
}

func scimActor(r *http.Request) *models.User {
	prefix := ""
	if token := scimTokenKey.Value(r.Context()); token != nil {
		prefix = token.Prefix
	}
	return &models.User{Email: storage.NullString("scim:" + prefix)}
}

func (a *API) auditSCIM(tx *storage.Connection, r *http.Request, actor *models.User, action models.AuditAction, providerID uuid.UUID, traits map[string]any) error {
	traits["sso_provider_id"] = providerID
	traits["outcome"] = "success"
	return models.NewAuditLogEntry(a.config.AuditLog, r, tx, actor, action, utilities.GetIPAddress(r), traits)
}

func scimMemberTraits(groupID, scimUserID uuid.UUID, userID *uuid.UUID) map[string]any {
	traits := map[string]any{
		"scim_group_id": groupID,
		"scim_user_id":  scimUserID,
	}
	if userID != nil {
		traits["user_id"] = *userID
	}
	return traits
}
