package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var _ server.AttributePatcher[*core.Group] = (*scimGroupRepository)(nil)

type scimGroupRepository struct {
	api *API
}

type scimGroupWrite func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, bool, error)

type scimGroupChange struct {
	r       *http.Request
	action  models.AuditAction
	members []uuid.UUID
}

func (s *scimGroupRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.Group, int, error) {
	return scimLister[models.SCIMGroup, *core.Group]{
		schemas: scimGroupSchemas,
		name:    "displayName",
		find:    models.FindSCIMGroups,
		render:  s.render,
	}.list(ctx, s.api.db.WithContext(ctx), query)
}

func (s *scimGroupRepository) Get(ctx context.Context, id string) (*core.Group, error) {
	target, err := scimTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	row, err := models.FindSCIMGroup(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, scimError(err)
	}
	return s.renderOne(db, target.ProviderID, row, protocol.ProjectionFrom(ctx))
}

func (s *scimGroupRepository) Create(ctx context.Context, group *core.Group) (*core.Group, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, models.SCIMGroupCreatedAction, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, bool, error) {
		row, err := models.CreateSCIMGroup(tx, providerID, resource)
		return row, true, err
	})
}

func (s *scimGroupRepository) Replace(ctx context.Context, group *core.Group) (*core.Group, error) {
	target, err := scimTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, models.SCIMGroupUpdatedAction, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, bool, error) {
		return models.ReplaceSCIMGroupIfChanged(tx, target, resource)
	})
}

func (s *scimGroupRepository) PatchAttribute(ctx context.Context, id, version string, delta server.AttributeDelta) (core.Meta, bool, error) {
	if !strings.EqualFold(delta.Attribute, "members") {
		return core.Meta{}, false, scimerrors.ErrInvalidPath(strconv.Quote(delta.Attribute) + " is unknown")
	}
	target, err := scimTarget(ctx, id, version)
	if err != nil {
		return core.Meta{}, false, err
	}
	add, err := scimAddedMemberIDs(delta.Added)
	if err != nil {
		return core.Meta{}, false, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return core.Meta{}, false, err
	}
	var (
		row     *models.SCIMGroup
		changed bool
	)
	err = s.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var terr error
		row, changed, terr = s.patchMembers(tx, r, target, scimMemberDiff{added: add, removed: scimRemovedMemberIDs(delta.Removed)})
		return terr
	})
	if err != nil {
		return core.Meta{}, false, scimError(err)
	}
	return scimMeta(scimResourceTypeGroup, scimBaseURL(s.api.config)+"/Groups/"+row.ID.String(), row.CreatedAt, row.UpdatedAt), changed, nil
}

func (s *scimGroupRepository) Delete(ctx context.Context, id, version string) error {
	target, err := scimTarget(ctx, id, version)
	if err != nil {
		return err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	return scimError(s.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		return s.delete(tx, r, target)
	}))
}

func (s *scimGroupRepository) delete(tx *storage.Connection, r *http.Request, target models.SCIMTarget) error {
	row, err := models.FindSCIMGroupForUpdate(tx, target.ProviderID, target.ID)
	if err != nil {
		return err
	}
	removed, err := models.ClearSCIMGroupMembers(tx, row.ID)
	if err != nil {
		return err
	}
	if row, err = models.DeleteSCIMGroup(tx, target); err != nil {
		return err
	}
	events, err := s.memberEvents(tx, r, row, scimMemberDiff{removed: removed})
	if err != nil {
		return err
	}
	deleted, err := s.groupEvent(r, models.SCIMGroupDeletedAction, row)
	if err != nil {
		return err
	}
	return s.api.auditSCIMEvents(tx, r, append(events, deleted))
}

func (s *scimGroupRepository) patchMembers(tx *storage.Connection, r *http.Request, target models.SCIMTarget, delta scimMemberDiff) (*models.SCIMGroup, bool, error) {
	row, err := models.LockSCIMGroup(tx, target)
	if err != nil {
		return nil, false, err
	}
	added, removed, err := models.PatchSCIMGroupMembers(tx, row, delta.added, delta.removed)
	if err != nil || len(added)+len(removed) == 0 {
		return row, false, err
	}
	if row, err = models.TouchSCIMGroup(tx, row); err != nil {
		return nil, false, err
	}
	events, err := s.memberEvents(tx, r, row, scimMemberDiff{added: added, removed: removed})
	if err != nil {
		return nil, false, err
	}
	return row, true, s.api.auditSCIMEvents(tx, r, events)
}

func (s *scimGroupRepository) save(ctx context.Context, action models.AuditAction, group *core.Group, write scimGroupWrite) (*core.Group, error) {
	members, err := scimMemberIDs(group.Members)
	if err != nil {
		return nil, err
	}
	attributes := *group
	attributes.Members = nil
	resource, err := scimEncode(&attributes, "id", "meta", "members")
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	change := scimGroupChange{r: r, action: action, members: members}
	db := s.api.db.WithContext(ctx)
	var saved *core.Group
	err = db.Transaction(func(tx *storage.Connection) error {
		row, changed, terr := write(tx, resource)
		if terr != nil {
			return terr
		}
		row, members, terr := s.applyMembers(tx, change, row, changed)
		if terr != nil {
			return terr
		}
		saved, terr = s.compose(*row, scimMembers(scimBaseURL(s.api.config), members))
		return terr
	})
	if err != nil {
		return nil, scimError(err)
	}
	return saved, nil
}

func (s *scimGroupRepository) applyMembers(tx *storage.Connection, change scimGroupChange, row *models.SCIMGroup, changed bool) (*models.SCIMGroup, []uuid.UUID, error) {
	added, removed, members, err := models.ReplaceSCIMGroupMembers(tx, row, change.members)
	if err != nil {
		return nil, nil, err
	}
	events := []scimAuditEvent{}
	switch {
	case changed:
		var event scimAuditEvent
		event, err = s.groupEvent(change.r, change.action, row)
		events = append(events, event)
	case len(added) > 0 || len(removed) > 0:
		row, err = models.TouchSCIMGroup(tx, row)
	default:
		return row, members, nil
	}
	if err != nil {
		return nil, nil, err
	}
	memberEvents, err := s.memberEvents(tx, change.r, row, scimMemberDiff{added: added, removed: removed})
	if err != nil {
		return nil, nil, err
	}
	return row, members, s.api.auditSCIMEvents(tx, change.r, append(events, memberEvents...))
}

func (s *scimGroupRepository) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) ([]*core.Group, error) {
	members, err := s.members(tx, providerID, rows, projection)
	if err != nil {
		return nil, err
	}
	groups := make([]*core.Group, 0, len(rows))
	for _, row := range rows {
		group, err := s.compose(row, members[row.ID])
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (s *scimGroupRepository) compose(row models.SCIMGroup, members []core.Member) (*core.Group, error) {
	group := &core.Group{}
	if err := json.Unmarshal(row.Resource, group); err != nil {
		return nil, err
	}
	group.ID = row.ID.String()
	group.Schemas = []core.SchemaURI{core.SchemaGroup}
	group.Meta = scimMeta(scimResourceTypeGroup, scimBaseURL(s.api.config)+"/Groups/"+group.ID, row.CreatedAt, row.UpdatedAt)
	group.Members = members
	return group, nil
}

func (s *scimGroupRepository) members(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) (map[uuid.UUID][]core.Member, error) {
	members := map[uuid.UUID][]core.Member{}
	if !projection.Returns("members") {
		return members, nil
	}
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	memberships, err := models.FindSCIMMembershipsByGroup(tx, providerID, ids)
	if err != nil {
		return nil, err
	}
	counts := make(map[uuid.UUID]int, len(rows))
	for _, m := range memberships {
		counts[m.GroupID]++
	}
	byGroup := make(map[uuid.UUID][]uuid.UUID, len(counts))
	for _, m := range memberships {
		if byGroup[m.GroupID] == nil {
			byGroup[m.GroupID] = make([]uuid.UUID, 0, counts[m.GroupID])
		}
		byGroup[m.GroupID] = append(byGroup[m.GroupID], m.SCIMUserID)
	}
	base := scimBaseURL(s.api.config)
	for groupID, scimUserIDs := range byGroup {
		members[groupID] = scimMembers(base, scimUserIDs)
	}
	return members, nil
}

func scimMembers(base string, scimUserIDs []uuid.UUID) []core.Member {
	members := make([]core.Member, len(scimUserIDs))
	for i, scimUserID := range scimUserIDs {
		id := scimUserID.String()
		members[i] = core.Member{Value: id, Ref: base + "/Users/" + id, Type: scimResourceTypeUser}
	}
	return members
}

func (s *scimGroupRepository) renderOne(tx *storage.Connection, providerID uuid.UUID, row *models.SCIMGroup, projection protocol.Projection) (*core.Group, error) {
	groups, err := s.render(tx, providerID, []models.SCIMGroup{*row}, projection)
	if err != nil {
		return nil, err
	}
	return groups[0], nil
}

func (s *scimGroupRepository) groupEvent(r *http.Request, action models.AuditAction, row *models.SCIMGroup) (scimAuditEvent, error) {
	var resource struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(row.Resource, &resource); err != nil {
		return scimAuditEvent{}, err
	}
	return scimAuditEvent{
		actor:      scimActor(r),
		action:     action,
		providerID: row.SSOProviderID,
		traits: map[string]any{
			"scim_group_id": row.ID,
			"display_name":  resource.DisplayName,
		},
	}, nil
}

type scimMemberDiff struct {
	added, removed []uuid.UUID
}

func (s *scimGroupRepository) memberEvents(tx *storage.Connection, r *http.Request, row *models.SCIMGroup, diff scimMemberDiff) ([]scimAuditEvent, error) {
	links, err := models.FindSCIMUserLinks(tx, slices.Concat(diff.added, diff.removed))
	if err != nil {
		return nil, err
	}
	actor := scimActor(r)
	events := make([]scimAuditEvent, 0, len(diff.added)+len(diff.removed))
	for _, change := range []struct {
		action models.AuditAction
		ids    []uuid.UUID
	}{
		{action: models.SCIMGroupMemberAddedAction, ids: diff.added},
		{action: models.SCIMGroupMemberRemovedAction, ids: diff.removed},
	} {
		for _, id := range change.ids {
			var userID *uuid.UUID
			if linked, ok := links[id]; ok {
				userID = &linked
			}
			events = append(events, scimAuditEvent{
				actor:      actor,
				action:     change.action,
				providerID: row.SSOProviderID,
				traits:     scimMemberTraits(row.ID, id, userID),
			})
		}
	}
	return events, nil
}

func scimMemberIDs(members []core.Member) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(members))
	for _, member := range members {
		id, err := uuid.FromString(member.Value)
		if err != nil {
			return nil, errSCIMMemberNotFound()
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func scimAddedMemberIDs(added []core.Object) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(added))
	for _, object := range added {
		value, _ := object.Get("value").(string)
		id, err := uuid.FromString(value)
		if err != nil {
			return nil, errSCIMMemberNotFound()
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func scimRemovedMemberIDs(removed []string) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(removed))
	for _, value := range removed {
		if id, err := uuid.FromString(value); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}
