package models

import (
	"bytes"
	"fmt"
	"slices"
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
	tableName:  SCIMGroup{}.TableName(),
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

func LockSCIMGroup(tx *storage.Connection, target SCIMTarget) (*SCIMGroup, error) {
	return lockSCIMRow[SCIMGroup](tx, scimGroupsTable, target)
}

func ReplaceSCIMGroupIfChanged(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMGroup, bool, error) {
	return replaceSCIMRowIfChanged[SCIMGroup](tx, scimGroupsTable, target, resource)
}

func TouchSCIMGroup(tx *storage.Connection, group *SCIMGroup) (*SCIMGroup, error) {
	touched := &SCIMGroup{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET updated_at = clock_timestamp() WHERE id = ? RETURNING "+scimGroupColumns, scimGroupsTable.tableName),
		group.ID,
	).First(touched); err != nil {
		return nil, errors.Wrap(err, "error updating SCIM group")
	}
	return touched, nil
}

func DeleteSCIMGroup(tx *storage.Connection, target SCIMTarget) (*SCIMGroup, error) {
	group := &SCIMGroup{}
	err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE %s AND "+scimVersionClause+" RETURNING %s", scimGroupsTable.tableName, scimGroupsTable.targetClause(), scimGroupsTable.columns),
		target.ID, target.ProviderID, target.UpdatedAt, target.UpdatedAt,
	).First(group)
	if err != nil {
		return nil, scimGroupsTable.writeError(tx, target, err, "deleting")
	}
	return group, nil
}

func FindSCIMMembershipsByGroup(tx *storage.Connection, providerID uuid.UUID, groupIDs []uuid.UUID) ([]SCIMGroupMembership, error) {
	members := []SCIMGroupMembership{}
	if len(groupIDs) == 0 {
		return members, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT m.group_id, m.scim_user_id FROM %q m JOIN %q u ON u.id = m.scim_user_id WHERE m.group_id = ANY(?::uuid[]) AND u.sso_provider_id = ? AND u.deleted_at IS NULL ORDER BY m.group_id, m.created_at, m.scim_user_id", SCIMGroupMember{}.TableName(), scimUsersTable.tableName),
		groupIDs, providerID,
	).All(&members)
	if err != nil {
		return nil, errors.Wrap(err, "error finding SCIM group members")
	}
	return members, nil
}

func FindSCIMMembershipsByUser(tx *storage.Connection, providerID uuid.UUID, scimUserIDs []uuid.UUID) ([]SCIMGroupMembership, error) {
	memberships := []SCIMGroupMembership{}
	if len(scimUserIDs) == 0 {
		return memberships, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT m.group_id, m.scim_user_id, g.resource->>'displayName' AS display FROM %q m JOIN %q g ON g.id = m.group_id WHERE m.scim_user_id = ANY(?::uuid[]) AND g.sso_provider_id = ? ORDER BY m.scim_user_id, g.display_name COLLATE \"C\", g.id", SCIMGroupMember{}.TableName(), scimGroupsTable.tableName),
		scimUserIDs, providerID,
	).All(&memberships)
	if err != nil {
		return nil, errors.Wrap(err, "error finding SCIM groups for users")
	}
	return memberships, nil
}

func ReplaceSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, scimUserIDs []uuid.UUID) (added, removed, members []uuid.UUID, err error) {
	current, err := findSCIMGroupMemberIDs(tx, group.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	if removed, err = removeSCIMGroupMembers(tx, group.ID, differenceUUIDs(current, scimUserIDs)); err != nil {
		return nil, nil, nil, err
	}
	added, err = addSCIMGroupMembers(tx, group, differenceUUIDs(scimUserIDs, current))
	if err != nil {
		return nil, nil, nil, err
	}
	return added, removed, append(differenceUUIDs(current, removed), added...), nil
}

func PatchSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, add, remove []uuid.UUID) (added, removed []uuid.UUID, err error) {
	if removed, err = removeSCIMGroupMembers(tx, group.ID, remove); err != nil {
		return nil, nil, err
	}
	if added, err = addSCIMGroupMembers(tx, group, add); err != nil {
		return nil, nil, err
	}
	return added, removed, nil
}

func ClearSCIMGroupMembers(tx *storage.Connection, groupID uuid.UUID) ([]uuid.UUID, error) {
	removed := []uuid.UUID{}
	if err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE group_id = ? RETURNING scim_user_id", SCIMGroupMember{}.TableName()),
		groupID,
	).All(&removed); err != nil {
		return nil, errors.Wrap(err, "error removing SCIM group members")
	}
	return removed, nil
}

func RemoveSCIMUserFromGroups(tx *storage.Connection, scimUserID uuid.UUID) ([]uuid.UUID, error) {
	groups, members := scimGroupsTable.tableName, SCIMGroupMember{}.TableName()
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
			fmt.Sprintf("UPDATE %q SET updated_at = clock_timestamp() WHERE id = ANY(?::uuid[])", groups),
			groupIDs,
		).Exec(); err != nil {
			return nil, errors.Wrap(err, "error updating SCIM groups")
		}
	}
	return groupIDs, nil
}

func replaceSCIMGroup(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMGroup, error) {
	return replaceSCIMRow[SCIMGroup](tx, scimGroupsTable, target, resource)
}

func lockLiveSCIMUserIDs(tx *storage.Connection, providerID uuid.UUID, ids []uuid.UUID) ([]uuid.UUID, error) {
	found := []uuid.UUID{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT id FROM %q WHERE id = ANY(?::uuid[]) AND sso_provider_id = ? AND deleted_at IS NULL ORDER BY id FOR SHARE", scimUsersTable.tableName),
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
	ids := []uuid.UUID{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT scim_user_id FROM %q WHERE group_id = ? ORDER BY created_at, scim_user_id", SCIMGroupMember{}.TableName()),
		groupID,
	).All(&ids); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM group members")
	}
	return ids, nil
}

func removeSCIMGroupMembers(tx *storage.Connection, groupID uuid.UUID, scimUserIDs []uuid.UUID) ([]uuid.UUID, error) {
	removed := []uuid.UUID{}
	if len(scimUserIDs) == 0 {
		return removed, nil
	}
	if err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE group_id = ? AND scim_user_id = ANY(?::uuid[]) RETURNING scim_user_id", SCIMGroupMember{}.TableName()),
		groupID, scimUserIDs,
	).All(&removed); err != nil {
		return nil, errors.Wrap(err, "error removing SCIM group members")
	}
	return removed, nil
}

func addSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, scimUserIDs []uuid.UUID) ([]uuid.UUID, error) {
	added := []uuid.UUID{}
	if len(scimUserIDs) == 0 {
		return added, nil
	}
	locked, err := lockLiveSCIMUserIDs(tx, group.SSOProviderID, scimUserIDs)
	if err != nil {
		return nil, err
	}
	if err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (group_id, scim_user_id) SELECT ?, unnest(?::uuid[]) ON CONFLICT DO NOTHING RETURNING scim_user_id", SCIMGroupMember{}.TableName()),
		group.ID, locked,
	).All(&added); err != nil {
		return nil, errors.Wrap(err, "error adding SCIM group members")
	}
	slices.SortFunc(added, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	return added, nil
}
