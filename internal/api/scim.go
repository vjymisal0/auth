package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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
)

const (
	scimBasePath          = "/scim/v2"
	scimResourceTypeUser  = "User"
	scimResourceTypeGroup = "Group"
)

type scimLister[Row, Resource any] struct {
	schemas core.Schemas
	name    string
	find    func(*storage.Connection, uuid.UUID, models.SCIMQuery) ([]Row, int, error)
	render  func(*storage.Connection, uuid.UUID, []Row, protocol.Projection) ([]Resource, error)
}

type scimAuditEvent struct {
	actor      *models.User
	action     models.AuditAction
	providerID uuid.UUID
	traits     map[string]any
}

var (
	errMissingSSOProvider = errors.New("scim: request has no SSO provider")

	scimUserSchemas = core.Schemas{
		core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
		core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
	}
	scimGroupSchemas = newSCIMGroupSchemas()
)

func (l scimLister[Row, Resource]) list(ctx context.Context, db *storage.Connection, query *protocol.SearchRequest) ([]Resource, int, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := scimSearch(query, l.schemas, l.name)
	if err != nil {
		return nil, 0, err
	}
	rows, total, err := l.find(db, providerID, search)
	if err != nil {
		return nil, 0, err
	}
	resources, err := l.render(db, providerID, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	return resources, total, nil
}

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

func (a *API) auditSCIM(tx *storage.Connection, r *http.Request, event scimAuditEvent) error {
	return a.auditSCIMEvents(tx, r, []scimAuditEvent{event})
}

func (a *API) auditSCIMEvents(tx *storage.Connection, r *http.Request, events []scimAuditEvent) error {
	entries := make([]models.AuditEvent, len(events))
	for i, event := range events {
		event.traits["sso_provider_id"] = event.providerID
		event.traits["outcome"] = "success"
		entries[i] = models.AuditEvent{Actor: event.actor, Action: event.action, Traits: event.traits}
	}
	return models.NewAuditLogEntries(a.config.AuditLog, r, tx, entries)
}

func scimBaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + scimBasePath
}

func scimLogError(r *http.Request, err error) {
	observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
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

func scimTarget(ctx context.Context, id, version string) (models.SCIMTarget, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return models.SCIMTarget{}, err
	}
	resourceID, err := uuid.FromString(id)
	if err != nil {
		return models.SCIMTarget{}, errSCIMNotFound()
	}
	updatedAt, err := scimParseVersion(version)
	if err != nil {
		return models.SCIMTarget{}, err
	}
	return models.SCIMTarget{ProviderID: providerID, ID: resourceID, UpdatedAt: updatedAt}, nil
}

func scimProviderID(ctx context.Context) (uuid.UUID, error) {
	token := scimTokenKey.Value(ctx)
	if token == nil || token.SSOProviderID == uuid.Nil {
		return uuid.Nil, errMissingSSOProvider
	}
	return token.SSOProviderID, nil
}

func scimProviderType(providerID uuid.UUID) string {
	return "sso:" + providerID.String()
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

func scimActor(r *http.Request) *models.User {
	prefix := ""
	if token := scimTokenKey.Value(r.Context()); token != nil {
		prefix = token.Prefix
	}
	return &models.User{Email: storage.NullString("scim:" + prefix)}
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
