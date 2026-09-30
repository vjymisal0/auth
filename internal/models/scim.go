package models

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMFilter struct {
	Name       *string
	ExternalID *string
}

type SCIMSortKey int

const (
	SCIMSortByCreatedAt SCIMSortKey = iota
	SCIMSortByID
	SCIMSortByName
	SCIMSortByUpdatedAt
)

type SCIMOrder struct {
	By         SCIMSortKey
	Descending bool
}

type SCIMQuery struct {
	Filter SCIMFilter
	Order  SCIMOrder
	Offset int
	Limit  int
}

type scimTable struct {
	name     string
	label    string
	columns  string
	nameCol  string
	live     string
	notFound error
	stale    error
	conflict error
}

func findSCIMPage[T any](tx *storage.Connection, table scimTable, providerID uuid.UUID, query SCIMQuery) ([]T, int, error) {
	where, args := table.where(providerID, query.Filter)
	total, err := tx.Q().Where(where, args...).Count(new(T))
	if err != nil {
		return nil, 0, errors.Wrapf(err, "error counting %s", table.name)
	}
	rows := []T{}
	if query.Limit <= 0 || query.Offset >= total {
		return rows, total, nil
	}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT %s FROM %q WHERE %s ORDER BY %s OFFSET ? LIMIT ?", table.columns, table.name, where, table.orderBy(query.Order)),
		append(args, query.Offset, query.Limit)...,
	).All(&rows); err != nil {
		return nil, 0, errors.Wrapf(err, "error finding %s", table.name)
	}
	return rows, total, nil
}

func createSCIMRow[T any](tx *storage.Connection, table scimTable, providerID uuid.UUID, resource []byte) (*T, error) {
	row := new(T)
	if err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (id, sso_provider_id, resource) VALUES (?, ?, ?::jsonb) RETURNING "+table.columns, table.name),
		uuid.Must(uuid.NewV4()), providerID, string(resource),
	).First(row); err != nil {
		return nil, table.error(err, "creating")
	}
	return row, nil
}

func findSCIMRow[T any](tx *storage.Connection, table scimTable, providerID, id uuid.UUID, lock string) (*T, error) {
	where := "id = ? AND sso_provider_id = ?"
	if table.live != "" {
		where += " AND " + table.live
	}
	row := new(T)
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT %s FROM %q WHERE %s%s", table.columns, table.name, where, lock),
		id, providerID,
	).First(row); err != nil {
		return nil, table.error(err, "finding")
	}
	return row, nil
}

func findUnchangedSCIMRow[T any](tx *storage.Connection, table scimTable, providerID, id uuid.UUID, resource []byte, updatedAt *time.Time) (*T, error) {
	where := "id = ? AND sso_provider_id = ? AND resource = ?::jsonb AND (?::timestamptz IS NULL OR updated_at = ?)"
	if table.live != "" {
		where += " AND " + table.live
	}
	row := new(T)
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT %s FROM %q WHERE %s FOR UPDATE", table.columns, table.name, where),
		id, providerID, string(resource), updatedAt, updatedAt,
	).First(row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, table.error(err, "finding")
	}
	return row, nil
}

func scimWriteError[T any](tx *storage.Connection, table scimTable, err error, providerID, id uuid.UUID, updatedAt *time.Time, verb string) error {
	if errors.Is(err, sql.ErrNoRows) && updatedAt != nil {
		if _, findErr := findSCIMRow[T](tx, table, providerID, id, ""); findErr != nil {
			return findErr
		}
		return table.stale
	}
	return table.error(err, verb)
}

func (t scimTable) where(providerID uuid.UUID, filter SCIMFilter) (string, []any) {
	clauses := []string{"sso_provider_id = ?"}
	args := []any{providerID}
	if t.live != "" {
		clauses = append(clauses, t.live)
	}
	if filter.Name != nil {
		clauses = append(clauses, t.nameCol+` COLLATE "C" = lower(?)`)
		args = append(args, *filter.Name)
	}
	if filter.ExternalID != nil {
		clauses = append(clauses, "external_id = ?")
		args = append(args, *filter.ExternalID)
	}
	return strings.Join(clauses, " AND "), args
}

func (t scimTable) orderBy(order SCIMOrder) string {
	direction := "ASC"
	if order.Descending {
		direction = "DESC"
	}
	switch order.By {
	case SCIMSortByID:
		return "id " + direction
	case SCIMSortByName:
		return t.nameCol + ` COLLATE "C" ` + direction + ", id " + direction
	case SCIMSortByUpdatedAt:
		return "updated_at " + direction + ", id " + direction
	}
	return "created_at " + direction + ", id " + direction
}

func (t scimTable) error(err error, verb string) error {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return t.notFound
	case isUniqueViolation(err):
		return t.conflict
	}
	return errors.Wrapf(err, "error %s %s", verb, t.label)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation
}

func isCheckViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.CheckViolation && pgErr.ConstraintName == constraint
}

func uuidArray(ids []uuid.UUID) string {
	values := make([]string, len(ids))
	for i, id := range ids {
		values[i] = id.String()
	}
	return "{" + strings.Join(values, ",") + "}"
}

func dedupeUUIDs(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	unique := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return unique
}

func differenceUUIDs(from, subtract []uuid.UUID) []uuid.UUID {
	exclude := make(map[uuid.UUID]struct{}, len(subtract))
	for _, id := range subtract {
		exclude[id] = struct{}{}
	}
	result := []uuid.UUID{}
	for _, id := range from {
		if _, ok := exclude[id]; !ok {
			result = append(result, id)
		}
	}
	return result
}
