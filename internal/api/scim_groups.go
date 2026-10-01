package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type scimGroupRepository struct {
	api *API
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
	return s.save(ctx, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, models.AuditAction, error) {
		row, err := models.CreateSCIMGroup(tx, providerID, resource)
		return row, models.SCIMGroupCreatedAction, err
	})
}

func (s *scimGroupRepository) Update(ctx context.Context, group *core.Group) (*core.Group, error) {
	target, err := scimTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, models.AuditAction, error) {
		row, changed, err := models.ReplaceSCIMGroupIfChanged(tx, target, resource)
		if !changed {
			return row, "", err
		}
		return row, models.SCIMGroupUpdatedAction, err
	})
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

func (s *scimGroupRepository) save(ctx context.Context, group *core.Group, write func(*storage.Connection, []byte) (*models.SCIMGroup, models.AuditAction, error)) (*core.Group, error) {
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
	var row *models.SCIMGroup
	var change models.SCIMGroupMemberChange
	err = s.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var action models.AuditAction
		var terr error
		if row, action, terr = write(tx, resource); terr != nil {
			return terr
		}
		if row, change, terr = models.ReplaceSCIMGroupMembers(tx, row, members); terr != nil {
			return terr
		}
		events, terr := s.memberEvents(tx, r, row, change)
		if terr != nil {
			return terr
		}
		return s.api.auditSCIMEvents(tx, r, append(s.groupEvents(r, action, row, group.DisplayName), events...))
	})
	if err != nil {
		return nil, scimError(err)
	}
	return s.compose(*row, scimMembers(scimBaseURL(s.api.config), change.Members))
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
	var resource struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(row.Resource, &resource); err != nil {
		return err
	}
	events, err := s.memberEvents(tx, r, row, models.SCIMGroupMemberChange{Removed: removed})
	if err != nil {
		return err
	}
	return s.api.auditSCIMEvents(tx, r, append(events, s.groupEvents(r, models.SCIMGroupDeletedAction, row, resource.DisplayName)...))
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

func (s *scimGroupRepository) renderOne(tx *storage.Connection, providerID uuid.UUID, row *models.SCIMGroup, projection protocol.Projection) (*core.Group, error) {
	groups, err := s.render(tx, providerID, []models.SCIMGroup{*row}, projection)
	if err != nil {
		return nil, err
	}
	return groups[0], nil
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
	base := scimBaseURL(s.api.config)
	for _, m := range memberships {
		if members[m.GroupID] == nil {
			members[m.GroupID] = make([]core.Member, 0, counts[m.GroupID])
		}
		members[m.GroupID] = append(members[m.GroupID], scimMember(base, m.SCIMUserID))
	}
	return members, nil
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

func (s *scimGroupRepository) groupEvents(r *http.Request, action models.AuditAction, row *models.SCIMGroup, displayName string) []scimAuditEvent {
	if action == "" {
		return nil
	}
	return []scimAuditEvent{{
		actor:      scimActor(r),
		action:     action,
		providerID: row.SSOProviderID,
		traits: map[string]any{
			"scim_group_id": row.ID,
			"display_name":  displayName,
		},
	}}
}

func (s *scimGroupRepository) memberEvents(tx *storage.Connection, r *http.Request, row *models.SCIMGroup, change models.SCIMGroupMemberChange) ([]scimAuditEvent, error) {
	links, err := models.FindSCIMUserLinks(tx, slices.Concat(change.Added, change.Removed))
	if err != nil {
		return nil, err
	}
	actor := scimActor(r)
	events := make([]scimAuditEvent, 0, len(change.Added)+len(change.Removed))
	appendEvents := func(action models.AuditAction, ids []uuid.UUID) {
		for _, id := range ids {
			var userID *uuid.UUID
			if linked, ok := links[id]; ok {
				userID = &linked
			}
			events = append(events, scimAuditEvent{
				actor:      actor,
				action:     action,
				providerID: row.SSOProviderID,
				traits:     scimMemberTraits(row.ID, id, userID),
			})
		}
	}
	appendEvents(models.SCIMGroupMemberAddedAction, change.Added)
	appendEvents(models.SCIMGroupMemberRemovedAction, change.Removed)
	return events, nil
}

func scimMembers(base string, scimUserIDs []uuid.UUID) []core.Member {
	members := make([]core.Member, len(scimUserIDs))
	for i, scimUserID := range scimUserIDs {
		members[i] = scimMember(base, scimUserID)
	}
	return members
}

func scimMember(base string, scimUserID uuid.UUID) core.Member {
	id := scimUserID.String()
	return core.Member{Value: id, Ref: base + "/Users/" + id, Type: scimResourceTypeUser}
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
