package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (a *API) deleteSCIMUsers(tx *storage.Connection, r *http.Request, actor *models.User, userID uuid.UUID) error {
	rows, err := models.SoftDeleteSCIMUsersByUserID(tx, userID)
	if err != nil {
		return err
	}
	for i := range rows {
		if err := a.removeSCIMUserFromGroups(tx, r, actor, &rows[i]); err != nil {
			return err
		}
		if err := a.auditSCIM(tx, r, actor, models.SCIMUserDeletedAction, rows[i].SSOProviderID, scimUserTraits(&rows[i])); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) removeSCIMUserFromGroups(tx *storage.Connection, r *http.Request, actor *models.User, row *models.SCIMUser) error {
	groupIDs, err := models.RemoveSCIMUserFromGroups(tx, row.ID)
	if err != nil {
		return err
	}
	for _, groupID := range groupIDs {
		if err := a.auditSCIM(tx, r, actor, models.SCIMGroupMemberRemovedAction, row.SSOProviderID, scimMemberTraits(groupID, row.ID, row.UserID)); err != nil {
			return err
		}
	}
	return nil
}
