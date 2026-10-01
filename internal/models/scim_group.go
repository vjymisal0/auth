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
	name:     SCIMGroup{}.TableName(),
	label:    "SCIM group",
	columns:  scimGroupColumns,
	nameCol:  "display_name",
	notFound: SCIMGroupNotFoundError{},
	stale:    SCIMGroupStaleError{},
	conflict: SCIMGroupConflictError{},
}

func CreateSCIMGroup(tx *storage.Connection, providerID uuid.UUID, resource []byte) (*SCIMGroup, error) {
	return createSCIMRow[SCIMGroup](tx, scimGroupsTable, providerID, resource)
}

func FindSCIMGroup(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMGroup, error) {
	return findSCIMRow[SCIMGroup](tx, scimGroupsTable, providerID, id, "")
}

func FindSCIMGroupForUpdate(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMGroup, error) {
	return findSCIMRow[SCIMGroup](tx, scimGroupsTable, providerID, id, " FOR UPDATE")
}

func FindSCIMGroups(tx *storage.Connection, providerID uuid.UUID, query SCIMQuery) ([]SCIMGroup, int, error) {
	return findSCIMPage[SCIMGroup](tx, scimGroupsTable, providerID, query)
}

func ReplaceSCIMGroup(tx *storage.Connection, providerID, id uuid.UUID, resource []byte, updatedAt *time.Time) (*SCIMGroup, error) {
	group := &SCIMGroup{}
	err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET resource = ?::jsonb, updated_at = now() WHERE id = ? AND sso_provider_id = ? AND (?::timestamptz IS NULL OR updated_at = ?) RETURNING "+scimGroupColumns, group.TableName()),
		string(resource), id, providerID, updatedAt, updatedAt,
	).First(group)
	if err != nil {
		return nil, scimWriteError[SCIMGroup](tx, scimGroupsTable, err, providerID, id, updatedAt, "replacing")
	}
	return group, nil
}

func FindUnchangedSCIMGroup(tx *storage.Connection, providerID, id uuid.UUID, resource []byte, updatedAt *time.Time) (*SCIMGroup, error) {
	return findUnchangedSCIMRow[SCIMGroup](tx, scimGroupsTable, providerID, id, resource, updatedAt)
}

func TouchSCIMGroup(tx *storage.Connection, group *SCIMGroup) (*SCIMGroup, error) {
	touched := &SCIMGroup{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET updated_at = now() WHERE id = ? RETURNING "+scimGroupColumns, group.TableName()),
		group.ID,
	).First(touched); err != nil {
		return nil, errors.Wrap(err, "error updating SCIM group")
	}
	return touched, nil
}

func DeleteSCIMGroup(tx *storage.Connection, providerID, id uuid.UUID, updatedAt *time.Time) (*SCIMGroup, error) {
	group := &SCIMGroup{}
	err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE id = ? AND sso_provider_id = ? AND (?::timestamptz IS NULL OR updated_at = ?) RETURNING "+scimGroupColumns, group.TableName()),
		id, providerID, updatedAt, updatedAt,
	).First(group)
	if err != nil {
		return nil, scimWriteError[SCIMGroup](tx, scimGroupsTable, err, providerID, id, updatedAt, "deleting")
	}
	return group, nil
}

func FindSCIMGroupMembers(tx *storage.Connection, providerID uuid.UUID, groupIDs []uuid.UUID) ([]SCIMGroupMembership, error) {
	members := []SCIMGroupMembership{}
	if len(groupIDs) == 0 {
		return members, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT m.group_id, m.scim_user_id, u.resource->>'userName' AS display FROM %q m JOIN %q u ON u.id = m.scim_user_id WHERE m.group_id = ANY(?::uuid[]) AND u.sso_provider_id = ? AND u.deleted_at IS NULL ORDER BY m.group_id, m.created_at, m.scim_user_id", (&SCIMGroupMember{}).TableName(), (&SCIMUser{}).TableName()),
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
		fmt.Sprintf("SELECT m.group_id, m.scim_user_id, g.resource->>'displayName' AS display FROM %q m JOIN %q g ON g.id = m.group_id WHERE m.scim_user_id = ANY(?::uuid[]) AND g.sso_provider_id = ? ORDER BY m.scim_user_id, g.display_name COLLATE \"C\", g.id", (&SCIMGroupMember{}).TableName(), (&SCIMGroup{}).TableName()),
		scimUserIDs, providerID,
	).All(&groups)
	if err != nil {
		return nil, errors.Wrap(err, "error finding SCIM groups for users")
	}
	return groups, nil
}

func ReplaceSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, scimUserIDs []uuid.UUID) (added, removed []uuid.UUID, err error) {
	wanted := []uuid.UUID{}
	if len(scimUserIDs) > 0 {
		if err := tx.RawQuery(
			fmt.Sprintf("SELECT id FROM %q WHERE id = ANY(?::uuid[]) AND sso_provider_id = ? AND deleted_at IS NULL", (&SCIMUser{}).TableName()),
			scimUserIDs, group.SSOProviderID,
		).All(&wanted); err != nil {
			return nil, nil, errors.Wrap(err, "error finding SCIM group members")
		}
	}
	if missing := differenceUUIDs(scimUserIDs, wanted); len(missing) > 0 {
		return nil, nil, SCIMGroupMemberNotFoundError{IDs: missing}
	}

	current := []SCIMGroupMember{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT group_id, scim_user_id, created_at FROM %q WHERE group_id = ?", (&SCIMGroupMember{}).TableName()),
		group.ID,
	).All(&current); err != nil {
		return nil, nil, errors.Wrap(err, "error finding SCIM group members")
	}
	currentIDs := make([]uuid.UUID, len(current))
	for i := range current {
		currentIDs[i] = current[i].SCIMUserID
	}

	removed = differenceUUIDs(currentIDs, wanted)
	added = differenceUUIDs(wanted, currentIDs)

	if len(removed) > 0 {
		if err := tx.RawQuery(
			fmt.Sprintf("DELETE FROM %q WHERE group_id = ? AND scim_user_id = ANY(?::uuid[])", (&SCIMGroupMember{}).TableName()),
			group.ID, removed,
		).Exec(); err != nil {
			return nil, nil, errors.Wrap(err, "error removing SCIM group members")
		}
	}
	if len(added) > 0 {
		locked := []uuid.UUID{}
		if err := tx.RawQuery(
			fmt.Sprintf("SELECT id FROM %q WHERE id = ANY(?::uuid[]) AND sso_provider_id = ? AND deleted_at IS NULL ORDER BY id FOR SHARE", (&SCIMUser{}).TableName()),
			added, group.SSOProviderID,
		).All(&locked); err != nil {
			return nil, nil, errors.Wrap(err, "error locking SCIM group members")
		}
		if missing := differenceUUIDs(added, locked); len(missing) > 0 {
			return nil, nil, SCIMGroupMemberNotFoundError{IDs: missing}
		}
		if err := tx.RawQuery(
			fmt.Sprintf("INSERT INTO %q (group_id, scim_user_id) SELECT ?, unnest(?::uuid[])", (&SCIMGroupMember{}).TableName()),
			group.ID, locked,
		).Exec(); err != nil {
			return nil, nil, errors.Wrap(err, "error adding SCIM group members")
		}
	}
	return added, removed, nil
}

func RemoveSCIMUserFromGroups(tx *storage.Connection, scimUserID uuid.UUID) ([]uuid.UUID, error) {
	groups, members := (&SCIMGroup{}).TableName(), (&SCIMGroupMember{}).TableName()
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
