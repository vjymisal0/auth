package models

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

type AuditLogEntryTestSuite struct {
	suite.Suite
	db    *storage.Connection
	r     *http.Request
	actor *User
}

func TestAuditLogEntry(t *testing.T) {
	ts := &AuditLogEntryTestSuite{db: setupSCIMTestDB(t)}
	defer func() { require.NoError(t, ts.db.Close()) }()
	suite.Run(t, ts)
}

func (ts *AuditLogEntryTestSuite) SetupTest() {
	require.NoError(ts.T(), TruncateAll(ts.db))
	ts.r = httptest.NewRequest(http.MethodGet, "/", nil)
	ts.r.Header.Set("User-Agent", "audit-test")
	actor, err := NewUser("", "bjensen@example.com", "", "authenticated", map[string]any{"full_name": "Barbara Jensen"})
	require.NoError(ts.T(), err)
	ts.actor = actor
}

func (ts *AuditLogEntryTestSuite) TestBatchMatchesSingleEntry() {
	single := ts.event(SCIMGroupMemberAddedAction, 1)
	require.NoError(ts.T(), NewAuditLogEntry(conf.AuditLogConfiguration{}, ts.r, ts.db, single.Actor, single.Action, "192.0.2.1", single.Traits))
	require.NoError(ts.T(), NewAuditLogEntries(conf.AuditLogConfiguration{}, ts.r, ts.db, []AuditEvent{ts.event(SCIMGroupMemberAddedAction, 1)}))

	entries := ts.entries()
	require.Len(ts.T(), entries, 2)
	require.Equal(ts.T(), entries[1].Payload, entries[0].Payload)
	require.Equal(ts.T(), entries[1].IPAddress, entries[0].IPAddress)
	require.NotEqual(ts.T(), entries[1].ID, entries[0].ID)
	require.False(ts.T(), entries[0].CreatedAt.IsZero())
}

func (ts *AuditLogEntryTestSuite) TestBatchKeepsEventOrder() {
	events := make([]AuditEvent, 500)
	for i := range events {
		events[i] = ts.event(SCIMGroupMemberRemovedAction, i)
	}
	require.NoError(ts.T(), NewAuditLogEntries(conf.AuditLogConfiguration{}, ts.r, ts.db, events))

	entries := ts.entries()
	require.Len(ts.T(), entries, len(events))
	for i, entry := range entries {
		require.EqualValues(ts.T(), len(events)-1-i, entry.Payload["traits"].(map[string]any)["n"])
		if i > 0 {
			require.True(ts.T(), entries[i-1].CreatedAt.After(entry.CreatedAt))
		}
	}
}

func (ts *AuditLogEntryTestSuite) TestBatchWithoutEvents() {
	require.NoError(ts.T(), NewAuditLogEntries(conf.AuditLogConfiguration{}, ts.r, ts.db, nil))
	require.Empty(ts.T(), ts.entries())
}

func (ts *AuditLogEntryTestSuite) TestBatchSkipsPostgresWhenDisabled() {
	events := []AuditEvent{ts.event(SCIMGroupMemberAddedAction, 1)}
	require.NoError(ts.T(), NewAuditLogEntries(conf.AuditLogConfiguration{DisablePostgres: true}, ts.r, ts.db, events))
	require.Empty(ts.T(), ts.entries())
}

func (ts *AuditLogEntryTestSuite) event(action AuditAction, n int) AuditEvent {
	return AuditEvent{Actor: ts.actor, Action: action, Traits: map[string]any{"n": n}}
}

func (ts *AuditLogEntryTestSuite) entries() []*AuditLogEntry {
	entries, err := FindAuditLogEntries(ts.db, nil, "", nil)
	require.NoError(ts.T(), err)
	return entries
}
