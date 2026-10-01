package models

import (
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMGroup struct {
	ID            uuid.UUID `db:"id"`
	SSOProviderID uuid.UUID `db:"sso_provider_id"`
	Resource      []byte    `db:"resource"`
	DisplayName   string    `db:"display_name"`
	ExternalID    *string   `db:"external_id"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}

const scimGroupColumns = "id, sso_provider_id, resource, display_name, external_id, created_at, updated_at"

func (SCIMGroup) TableName() string {
	return "scim_groups"
}

type SCIMGroupMember struct {
	GroupID    uuid.UUID `db:"group_id"`
	SCIMUserID uuid.UUID `db:"scim_user_id"`
	CreatedAt  time.Time `db:"created_at"`
}

func (SCIMGroupMember) TableName() string {
	return "scim_group_members"
}

type SCIMGroupMembership struct {
	GroupID    uuid.UUID `db:"group_id"`
	SCIMUserID uuid.UUID `db:"scim_user_id"`
	Display    string    `db:"display"`
}

var scimGroupsTable = scimTable{
	name:       SCIMGroup{}.TableName(),
	label:      "SCIM group",
	columns:    scimGroupColumns,
	nameColumn: "display_name",
	notFound:   SCIMGroupNotFoundError{},
	stale:      SCIMGroupStaleError{},
	conflict:   SCIMGroupConflictError{},
}

func CreateSCIMGroup(tx *storage.Connection, providerID uuid.UUID, resource []byte) (*SCIMGroup, error) {
	return createSCIMRow[SCIMGroup](tx, scimGroupsTable, providerID, resource)
}

func FindSCIMGroup(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMGroup, error) {
	return findSCIMRow[SCIMGroup](tx, scimGroupsTable, SCIMTarget{ProviderID: providerID, ID: id}, false)
}

func FindSCIMGroupForUpdate(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMGroup, error) {
	return findSCIMRow[SCIMGroup](tx, scimGroupsTable, SCIMTarget{ProviderID: providerID, ID: id}, true)
}

func FindSCIMGroups(tx *storage.Connection, providerID uuid.UUID, query SCIMQuery) ([]SCIMGroup, int, error) {
	return findSCIMPage[SCIMGroup](tx, scimGroupsTable, providerID, query)
}

func ReplaceSCIMGroup(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMGroup, error) {
	return replaceSCIMRow[SCIMGroup](tx, scimGroupsTable, target, resource)
}

func FindUnchangedSCIMGroup(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMGroup, error) {
	return findUnchangedSCIMRow[SCIMGroup](tx, scimGroupsTable, target, resource)
}

func TouchSCIMGroup(tx *storage.Connection, group *SCIMGroup) (*SCIMGroup, error) {
	touched := &SCIMGroup{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET updated_at = now() WHERE id = ? RETURNING "+scimGroupColumns, scimGroupsTable.name),
		group.ID,
	).First(touched); err != nil {
		return nil, errors.Wrap(err, "error updating SCIM group")
	}
	return touched, nil
}

func DeleteSCIMGroup(tx *storage.Connection, target SCIMTarget) (*SCIMGroup, error) {
	group := &SCIMGroup{}
	err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE id = ? AND sso_provider_id = ? AND (?::timestamptz IS NULL OR updated_at = ?) RETURNING "+scimGroupColumns, scimGroupsTable.name),
		target.ID, target.ProviderID, target.UpdatedAt, target.UpdatedAt,
	).First(group)
	if err != nil {
		return nil, scimGroupsTable.writeError(tx, target, err, "deleting")
	}
	return group, nil
}

func FindSCIMGroupMembers(tx *storage.Connection, providerID uuid.UUID, groupIDs []uuid.UUID) ([]SCIMGroupMembership, error) {
	members := []SCIMGroupMembership{}
	if len(groupIDs) == 0 {
		return members, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT m.group_id, m.scim_user_id, u.resource->>'userName' AS display FROM %q m JOIN %q u ON u.id = m.scim_user_id WHERE m.group_id = ANY(?::uuid[]) AND u.sso_provider_id = ? AND u.deleted_at IS NULL ORDER BY m.group_id, m.created_at, m.scim_user_id", SCIMGroupMember{}.TableName(), scimUsersTable.name),
		groupIDs, providerID,
	).All(&members)
	if err != nil {
		return nil, errors.Wrap(err, "error finding SCIM group members")
	}
	return members, nil
}

func FindSCIMGroupsForUsers(tx *storage.Connection, providerID uuid.UUID, scimUserIDs []uuid.UUID) ([]SCIMGroupMembership, error) {
	groups := []SCIMGroupMembership{}
	if len(scimUserIDs) == 0 {
		return groups, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT m.group_id, m.scim_user_id, g.resource->>'displayName' AS display FROM %q m JOIN %q g ON g.id = m.group_id WHERE m.scim_user_id = ANY(?::uuid[]) AND g.sso_provider_id = ? ORDER BY m.scim_user_id, g.display_name COLLATE \"C\", g.id", SCIMGroupMember{}.TableName(), scimGroupsTable.name),
		scimUserIDs, providerID,
	).All(&groups)
	if err != nil {
		return nil, errors.Wrap(err, "error finding SCIM groups for users")
	}
	return groups, nil
}

func ReplaceSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, scimUserIDs []uuid.UUID) (added, removed []uuid.UUID, err error) {
	current, err := findSCIMGroupMemberIDs(tx, group.ID)
	if err != nil {
		return nil, nil, err
	}
	removed = differenceUUIDs(current, scimUserIDs)
	if err := removeSCIMGroupMembers(tx, group.ID, removed); err != nil {
		return nil, nil, err
	}
	added, err = addSCIMGroupMembers(tx, group, differenceUUIDs(scimUserIDs, current))
	if err != nil {
		return nil, nil, err
	}
	return added, removed, nil
}

func RemoveSCIMUserFromGroups(tx *storage.Connection, scimUserID uuid.UUID) ([]uuid.UUID, error) {
	groups, members := scimGroupsTable.name, SCIMGroupMember{}.TableName()
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT id FROM %q WHERE id IN (SELECT group_id FROM %q WHERE scim_user_id = ?) ORDER BY id FOR UPDATE", groups, members),
		scimUserID,
	).Exec(); err != nil {
		return nil, errors.Wrap(err, "error locking SCIM groups")
	}
	removed := []SCIMGroupMember{}
	if err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE scim_user_id = ? RETURNING group_id, scim_user_id, created_at", members),
		scimUserID,
	).All(&removed); err != nil {
		return nil, errors.Wrap(err, "error removing SCIM user from groups")
	}
	groupIDs := make([]uuid.UUID, len(removed))
	for i := range removed {
		groupIDs[i] = removed[i].GroupID
	}
	if len(groupIDs) > 0 {
		if err := tx.RawQuery(
			fmt.Sprintf("UPDATE %q SET updated_at = now() WHERE id = ANY(?::uuid[])", groups),
			groupIDs,
		).Exec(); err != nil {
			return nil, errors.Wrap(err, "error updating SCIM groups")
		}
	}
	return groupIDs, nil
}

func lockLiveSCIMUserIDs(tx *storage.Connection, providerID uuid.UUID, ids []uuid.UUID) ([]uuid.UUID, error) {
	found := []uuid.UUID{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT id FROM %q WHERE id = ANY(?::uuid[]) AND sso_provider_id = ? AND deleted_at IS NULL ORDER BY id FOR SHARE", scimUsersTable.name),
		ids, providerID,
	).All(&found); err != nil {
		return nil, errors.Wrap(err, "error locking SCIM group members")
	}
	if missing := differenceUUIDs(ids, found); len(missing) > 0 {
		return nil, SCIMGroupMemberNotFoundError{IDs: missing}
	}
	return found, nil
}

func findSCIMGroupMemberIDs(tx *storage.Connection, groupID uuid.UUID) ([]uuid.UUID, error) {
	members := []SCIMGroupMember{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT group_id, scim_user_id, created_at FROM %q WHERE group_id = ?", SCIMGroupMember{}.TableName()),
		groupID,
	).All(&members); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM group members")
	}
	ids := make([]uuid.UUID, len(members))
	for i := range members {
		ids[i] = members[i].SCIMUserID
	}
	return ids, nil
}

func removeSCIMGroupMembers(tx *storage.Connection, groupID uuid.UUID, scimUserIDs []uuid.UUID) error {
	if len(scimUserIDs) == 0 {
		return nil
	}
	if err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE group_id = ? AND scim_user_id = ANY(?::uuid[])", SCIMGroupMember{}.TableName()),
		groupID, scimUserIDs,
	).Exec(); err != nil {
		return errors.Wrap(err, "error removing SCIM group members")
	}
	return nil
}

func addSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, scimUserIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(scimUserIDs) == 0 {
		return []uuid.UUID{}, nil
	}
	locked, err := lockLiveSCIMUserIDs(tx, group.SSOProviderID, scimUserIDs)
	if err != nil {
		return nil, err
	}
	if err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (group_id, scim_user_id) SELECT ?, unnest(?::uuid[])", SCIMGroupMember{}.TableName()),
		group.ID, locked,
	).Exec(); err != nil {
		return nil, errors.Wrap(err, "error adding SCIM group members")
	}
	return locked, nil
}
