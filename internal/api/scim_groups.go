package api

import (
	"context"
	"encoding/json"
	"net/http"

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
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := scimSearch(query, scimGroupSchemas, "displayName")
	if err != nil {
		return nil, 0, err
	}
	db := s.api.db.WithContext(ctx)
	rows, total, err := models.FindSCIMGroups(db, providerID, search)
	if err != nil {
		return nil, 0, err
	}
	groups, err := s.render(db, providerID, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	return groups, total, nil
}

func (s *scimGroupRepository) Get(ctx context.Context, id string) (*core.Group, error) {
	providerID, resourceID, _, err := scimTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	row, err := models.FindSCIMGroup(db, providerID, resourceID)
	if err != nil {
		return nil, scimError(err)
	}
	return s.renderOne(db, providerID, row, protocol.ProjectionFrom(ctx))
}

func (s *scimGroupRepository) Create(ctx context.Context, group *core.Group) (*core.Group, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, providerID, models.SCIMGroupCreatedAction, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, bool, error) {
		row, err := models.CreateSCIMGroup(tx, providerID, resource)
		return row, true, err
	})
}

func (s *scimGroupRepository) Replace(ctx context.Context, group *core.Group) (*core.Group, error) {
	providerID, id, updatedAt, err := scimTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, providerID, models.SCIMGroupUpdatedAction, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, bool, error) {
		unchanged, err := models.FindUnchangedSCIMGroup(tx, providerID, id, resource, updatedAt)
		if err != nil || unchanged != nil {
			return unchanged, false, err
		}
		row, err := models.ReplaceSCIMGroup(tx, providerID, id, resource, updatedAt)
		return row, true, err
	})
}

func (s *scimGroupRepository) Delete(ctx context.Context, id, version string) error {
	providerID, resourceID, updatedAt, err := scimTarget(ctx, id, version)
	if err != nil {
		return err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	return scimError(s.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := models.FindSCIMGroupForUpdate(tx, providerID, resourceID)
		if err != nil {
			return err
		}
		_, removed, err := models.ReplaceSCIMGroupMembers(tx, row, nil)
		if err != nil {
			return err
		}
		if row, err = models.DeleteSCIMGroup(tx, providerID, resourceID, updatedAt); err != nil {
			return err
		}
		if err := s.auditMembers(tx, r, row, nil, removed); err != nil {
			return err
		}
		return s.audit(tx, r, models.SCIMGroupDeletedAction, row)
	}))
}

func (s *scimGroupRepository) save(ctx context.Context, providerID uuid.UUID, action models.AuditAction, group *core.Group, write func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, bool, error)) (*core.Group, error) {
	members, err := scimMemberIDs(group.Members)
	if err != nil {
		return nil, err
	}
	resource, err := scimEncode(group, "id", "meta", "members")
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	var row *models.SCIMGroup
	err = db.Transaction(func(tx *storage.Connection) error {
		var (
			changed bool
			terr    error
		)
		if row, changed, terr = write(tx, resource); terr != nil {
			return terr
		}
		added, removed, terr := models.ReplaceSCIMGroupMembers(tx, row, members)
		if terr != nil {
			return terr
		}
		if !changed {
			if len(added) == 0 && len(removed) == 0 {
				return nil
			}
			if row, terr = models.TouchSCIMGroup(tx, row); terr != nil {
				return terr
			}
		} else if terr := s.audit(tx, r, action, row); terr != nil {
			return terr
		}
		return s.auditMembers(tx, r, row, added, removed)
	})
	if err != nil {
		return nil, scimError(err)
	}
	return s.renderOne(db, providerID, row, protocol.Projection{})
}

func (s *scimGroupRepository) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) ([]*core.Group, error) {
	memberships := []models.SCIMGroupMembership{}
	if projection.Returns("members") {
		ids := make([]uuid.UUID, len(rows))
		for i, row := range rows {
			ids[i] = row.ID
		}
		var err error
		if memberships, err = models.FindSCIMGroupMembers(tx, providerID, ids); err != nil {
			return nil, err
		}
	}
	base := scimBaseURL(s.api.config)
	members := map[uuid.UUID][]core.Member{}
	for _, m := range memberships {
		members[m.GroupID] = append(members[m.GroupID], core.Member{
			Value: m.SCIMUserID.String(),
			Ref:   base + "/Users/" + m.SCIMUserID.String(),
			Type:  scimResourceTypeUser,
		})
	}

	groups := make([]*core.Group, 0, len(rows))
	for _, row := range rows {
		group := &core.Group{}
		if err := json.Unmarshal(row.Resource, group); err != nil {
			return nil, err
		}
		group.ID = row.ID.String()
		group.Schemas = []core.SchemaURI{core.SchemaGroup}
		group.Meta = scimMeta(scimResourceTypeGroup, base+"/Groups/"+group.ID, row.CreatedAt, row.UpdatedAt)
		group.Members = members[row.ID]
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

func (s *scimGroupRepository) audit(tx *storage.Connection, r *http.Request, action models.AuditAction, row *models.SCIMGroup) error {
	var resource struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(row.Resource, &resource); err != nil {
		return err
	}
	return s.api.auditSCIM(tx, r, scimActor(r), action, row.SSOProviderID, map[string]any{
		"scim_group_id": row.ID,
		"display_name":  resource.DisplayName,
	})
}

func (s *scimGroupRepository) auditMembers(tx *storage.Connection, r *http.Request, row *models.SCIMGroup, added, removed []uuid.UUID) error {
	links, err := models.FindSCIMUserLinks(tx, append(append([]uuid.UUID{}, added...), removed...))
	if err != nil {
		return err
	}
	for _, change := range []struct {
		action models.AuditAction
		ids    []uuid.UUID
	}{
		{models.SCIMGroupMemberAddedAction, added},
		{models.SCIMGroupMemberRemovedAction, removed},
	} {
		for _, id := range change.ids {
			var userID *uuid.UUID
			if linked, ok := links[id]; ok {
				userID = &linked
			}
			if err := s.api.auditSCIM(tx, r, scimActor(r), change.action, row.SSOProviderID, scimMemberTraits(row.ID, id, userID)); err != nil {
				return err
			}
		}
	}
	return nil
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
