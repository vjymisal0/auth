package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (ts *SCIMUsersTestSuite) ssoUser(provider *models.SSOProvider, sub, email string) *models.User {
	user, err := models.NewUser("", email, "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	user.IsSSOUser = true
	require.NoError(ts.T(), ts.API.db.Create(user))
	identity, err := models.NewIdentity(user, "sso:"+provider.ID.String(), map[string]any{"sub": sub, "email": email})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(identity))
	return user
}

func (ts *SCIMUsersTestSuite) linkedUser(id string) *models.User {
	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))
	require.NotNil(ts.T(), row.UserID)
	user, err := models.FindUserByID(ts.API.db, *row.UserID)
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMUsersTestSuite) identities(user *models.User) []*models.Identity {
	identities, err := models.FindIdentitiesByUserID(ts.API.db, user.ID)
	require.NoError(ts.T(), err)
	return identities
}

func (ts *SCIMUsersTestSuite) TestCreateProvisionsSSOUser() {
	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.True(ts.T(), user.IsSSOUser)
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())
	require.Equal(ts.T(), ts.API.config.JWT.Aud, user.Aud)
	require.NotNil(ts.T(), user.EmailConfirmedAt)
	require.False(ts.T(), user.IsBanned())
	require.Equal(ts.T(), []any{"sso:" + ts.A.ID.String()}, user.AppMetaData["providers"])

	identities := ts.identities(user)
	require.Len(ts.T(), identities, 1)
	require.Equal(ts.T(), "sso:"+ts.A.ID.String(), identities[0].Provider)
	require.Equal(ts.T(), "Alice@Example.com", identities[0].ProviderID)
}

func (ts *SCIMUsersTestSuite) TestCreateDoesNotLinkOutsideProvider() {
	password, err := models.NewUser("", "alice@example.com", "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(password))
	other := ts.ssoUser(ts.B, "Alice@Example.com", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.NotEqual(ts.T(), password.ID, user.ID)
	require.NotEqual(ts.T(), other.ID, user.ID)
	require.Len(ts.T(), ts.identities(password), 0)
	require.Len(ts.T(), ts.identities(other), 1)
}

func (ts *SCIMUsersTestSuite) TestCreateReusesSAMLIdentity() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), existing.ID, user.ID)
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMUsersTestSuite) TestCreateLinksByEmailWithinProvider() {
	existing := ts.ssoUser(ts.A, "saml-name-id", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), existing.ID, user.ID)
	require.Len(ts.T(), ts.identities(user), 2)
}

func (ts *SCIMUsersTestSuite) passkeyRegistrationOptions(user *models.User) int {
	passkey, webauthn := ts.API.config.Passkey, ts.API.config.WebAuthn
	defer func() { ts.API.config.Passkey, ts.API.config.WebAuthn = passkey, webauthn }()
	ts.API.config.Passkey.Enabled = true
	ts.API.config.WebAuthn = conf.WebAuthnConfiguration{
		RPID:                    "localhost",
		RPDisplayName:           "Test App",
		RPOrigins:               []string{"http://localhost:3000"},
		ChallengeExpiryDuration: 5 * time.Minute,
	}

	session, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))
	token, _, err := ts.API.generateAccessToken(httptest.NewRequest(http.MethodPost, "/passkeys", nil), ts.API.db, user, &session.ID, models.PasswordGrant)
	require.NoError(ts.T(), err)

	r := httptest.NewRequest(http.MethodPost, "/passkeys/registration/options", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w.Code
}

func (ts *SCIMUsersTestSuite) TestPasswordUserWithSameEmailIsNeverLinked() {
	password, err := models.NewUser("", "alice@example.com", "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(password))

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.NotEqual(ts.T(), password.ID, user.ID)
	require.True(ts.T(), user.IsSSOUser)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, ts.passkeyRegistrationOptions(user))
	reloaded, err := models.FindUserByID(ts.API.db, password.ID)
	require.NoError(ts.T(), err)
	require.False(ts.T(), reloaded.IsSSOUser)
	require.Len(ts.T(), ts.identities(reloaded), 0)
}

func (ts *SCIMUsersTestSuite) TestLinkAccountKeepsUserSSO() {
	password, err := models.NewUser("", "alice@example.com", "", ts.API.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(password))
	existing := ts.ssoUser(ts.A, "saml-name-id", "alice@example.com")

	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), existing.ID, user.ID)
	require.Len(ts.T(), ts.identities(user), 2)
	require.True(ts.T(), user.IsSSOUser)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, ts.passkeyRegistrationOptions(user))
	require.Len(ts.T(), ts.identities(password), 0)
}

func (ts *SCIMUsersTestSuite) TestOldEmailCannotSignInAfterEmailChange() {
	id := ts.create(ts.TokenA, oktaUser)
	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, strings.Replace(oktaUser, `"value": "alice@example.com"`, `"value": "alice.smith@example.com"`, 1))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	user := ts.linkedUser(id)
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())

	for _, req := range []struct{ path, body string }{
		{"/recover", `{"email":"alice@example.com"}`},
		{"/otp", `{"email":"alice@example.com","create_user":false}`},
		{"/magiclink", `{"email":"alice@example.com"}`},
		{"/token?grant_type=password", `{"email":"alice@example.com","password":"hunter2hunter2"}`},
	} {
		r := httptest.NewRequest(http.MethodPost, req.path, strings.NewReader(req.body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, r)
		require.NotContains(ts.T(), w.Body.String(), "access_token", req.path)

		reloaded := ts.linkedUser(id)
		require.Nil(ts.T(), reloaded.RecoverySentAt, req.path)
		require.Empty(ts.T(), reloaded.RecoveryToken, req.path)
		require.Empty(ts.T(), reloaded.ConfirmationToken, req.path)
		count, err := ts.API.db.Q().Where("user_id = ?", user.ID).Count(&models.OneTimeToken{})
		require.NoError(ts.T(), err)
		require.Zero(ts.T(), count, req.path)
		require.Zero(ts.T(), ts.sessions(user), req.path)
	}
}

func (ts *SCIMUsersTestSuite) TestRemovingEmailsKeepsUserEmail() {
	id := ts.create(ts.TokenA, strings.Replace(oktaUser, `"userName": "Alice@Example.com"`, `"userName": "alice.smith"`, 1))
	user := ts.linkedUser(id)

	for _, userName := range []string{"alice.smith", "asmith"} {
		w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+userName+`","active":true}`)
		require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

		require.Equal(ts.T(), "alice@example.com", ts.linkedUser(id).GetEmail(), userName)
		identity, err := models.FindIdentityByIdAndProvider(ts.API.db, userName, "sso:"+ts.A.ID.String())
		require.NoError(ts.T(), err, userName)
		require.Equal(ts.T(), "alice@example.com", identity.IdentityData["email"], userName)

		signedIn, err := ts.samlLogin(ts.A, "saml-name-id-"+userName, "alice@example.com")
		require.NoError(ts.T(), err, userName)
		require.Equal(ts.T(), user.ID, signedIn.ID, userName)
	}
}

func (ts *SCIMUsersTestSuite) TestCreateInactiveLogsOutWithoutBanning() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	ts.session(existing)

	user := ts.linkedUser(ts.create(ts.TokenA, strings.Replace(oktaUser, `"active": true`, `"active": false`, 1)))

	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
}

func (ts *SCIMUsersTestSuite) TestCreateRejectsSharedUser() {
	ts.create(ts.TokenA, oktaUser)

	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", strings.Replace(oktaUser, `"userName": "Alice@Example.com"`, `"userName": "alice.smith"`, 1))
	require.Equal(ts.T(), http.StatusConflict, w.Code, w.Body.String())
	require.Equal(ts.T(), "uniqueness", body["scimType"])
	require.EqualValues(ts.T(), 0, ts.list(ts.TokenA, `userName eq "alice.smith"`)["totalResults"])
}

func (ts *SCIMUsersTestSuite) TestCreateRequiresEmail() {
	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice"}`)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])
}

func (ts *SCIMUsersTestSuite) TestCreateFallsBackToEmailUserName() {
	id := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Alice@Example.com"}`)
	user := ts.linkedUser(id)
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())

	signedIn, err := ts.samlLogin(ts.A, "saml-name-id", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), user.ID, signedIn.ID)
}

func (ts *SCIMUsersTestSuite) TestRejectsInvalidEmailsValue() {
	invalid := strings.Replace(oktaUser, `"value": "alice@example.com"`, `"value": "not-an-email"`, 1)
	w, body := ts.do(ts.TokenA, http.MethodPost, "/Users", invalid)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])

	id := ts.create(ts.TokenA, oktaUser)
	w, body = ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, invalid)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])

	w, body = ts.do(ts.TokenA, http.MethodPatch, "/Users/"+id, `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "path": "emails", "value": [{"value": "not-an-email", "primary": true}]}]
	}`)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	require.Equal(ts.T(), "invalidValue", body["scimType"])
	require.Equal(ts.T(), "alice@example.com", ts.linkedUser(id).GetEmail())
}

func (ts *SCIMUsersTestSuite) TestCreateKeepsAdminBan() {
	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), existing.Ban(ts.API.db, time.Hour))

	require.True(ts.T(), ts.linkedUser(ts.create(ts.TokenA, oktaUser)).IsBanned())
}

func (ts *SCIMUsersTestSuite) TestCreateLeavesNoUserOnConflict() {
	ts.create(ts.TokenA, userWith("alice@example.com", "a-1"))

	w, _ := ts.do(ts.TokenA, http.MethodPost, "/Users", userWith("bob@example.com", "a-1"))
	require.Equal(ts.T(), http.StatusConflict, w.Code)
	count, err := ts.API.db.Q().Where("email = ?", "bob@example.com").Count(&models.User{})
	require.NoError(ts.T(), err)
	require.Zero(ts.T(), count)
}

func (ts *SCIMUsersTestSuite) session(user *models.User) {
	session, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))
}

func (ts *SCIMUsersTestSuite) refreshToken(user *models.User) string {
	token, err := models.GrantAuthenticatedUser(ts.API.db, user, models.GrantParams{})
	require.NoError(ts.T(), err)
	return token.Token
}

func (ts *SCIMUsersTestSuite) refresh(token string) int {
	r := httptest.NewRequest(http.MethodPost, "/token?grant_type=refresh_token", strings.NewReader(`{"refresh_token":"`+token+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w.Code
}

func (ts *SCIMUsersTestSuite) sessions(user *models.User) int {
	count, err := ts.API.db.Q().Where("user_id = ?", user.ID).Count(&models.Session{})
	require.NoError(ts.T(), err)
	return count
}

func (ts *SCIMUsersTestSuite) samlLogin(ssoProvider *models.SSOProvider, sub, email string) (*models.User, error) {
	userData := &provider.UserProvidedData{
		Metadata: &provider.Claims{
			Subject:       sub,
			Email:         email,
			EmailVerified: true,
		},
		Emails: []provider.Email{{
			Email:    email,
			Primary:  true,
			Verified: true,
		}},
	}
	return ts.samlLoginWith(ssoProvider, userData)
}

func (ts *SCIMUsersTestSuite) samlLoginWith(ssoProvider *models.SSOProvider, userData *provider.UserProvidedData) (*models.User, error) {
	r := httptest.NewRequest(http.MethodPost, "/sso/saml/acs", nil)

	var user *models.User
	err := ts.API.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		_, user, terr = ts.API.createAccountFromExternalIdentity(tx, r, userData, "sso:"+ssoProvider.ID.String(), false)
		return terr
	})
	return user, err
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginLocksVerifiedEmailWithoutMetadataEmail() {
	userData := &provider.UserProvidedData{
		Metadata: &provider.Claims{Subject: "saml-name-id", EmailVerified: true},
		Emails:   []provider.Email{{Email: "Alice@Example.com", Primary: true, Verified: true}},
	}
	conn, err := ts.API.db.NewTransaction()
	require.NoError(ts.T(), err)
	tx := &storage.Connection{Connection: conn}
	require.NoError(ts.T(), models.LockAccountLinking(tx, "sso:"+ts.A.ID.String(), "alice@example.com"))

	done := make(chan error, 1)
	go func() {
		_, err := ts.samlLoginWith(ts.A, userData)
		done <- err
	}()

	select {
	case err := <-done:
		require.NoError(ts.T(), tx.TX.Rollback())
		require.FailNow(ts.T(), "SAML login did not wait for the account linking lock", "%v", err)
	case <-time.After(200 * time.Millisecond):
	}
	require.NoError(ts.T(), tx.TX.Rollback())
	require.NoError(ts.T(), <-done)
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginAllowedForActiveSCIMUser() {
	id := ts.create(ts.TokenA, oktaUser)
	linked := ts.linkedUser(id)

	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), linked.ID, user.ID)
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginAllowedForDeprovisionedUserWhileSCIMFlagOff() {
	id := ts.create(ts.TokenA, oktaUser)
	linked := ts.linkedUser(id)
	ts.setActive(id, false)
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), linked.ID, user.ID)
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginBlockedWhilePATCHedInactive() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.setActive(id, false)

	_, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)

	ts.setActive(id, true)
	linked := ts.linkedUser(id)

	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), linked.ID, user.ID)
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginBlockedAfterDelete() {
	id := ts.create(ts.TokenA, oktaUser)

	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	_, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)

	relinked := ts.linkedUser(ts.create(ts.TokenA, oktaUser))
	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), relinked.ID, user.ID)
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginBlockedWhenCreatedInactive() {
	id := ts.create(ts.TokenA, strings.Replace(oktaUser, `"active": true`, `"active": false`, 1))
	ts.linkedUser(id)

	_, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.Error(ts.T(), err)
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginAllowedWhenActiveOmitted() {
	id := ts.create(ts.TokenA, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Alice@Example.com","emails":[{"primary":true,"value":"alice@example.com"}]}`)
	linked := ts.linkedUser(id)

	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), linked.ID, user.ID)
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginAllowedWithoutSCIMRow() {
	existing := ts.ssoUser(ts.A, "jit-user", "jit@example.com")

	user, err := ts.samlLogin(ts.A, "jit-user", "jit@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), existing.ID, user.ID)
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginLinksDivergedNameIDToSCIMUser() {
	linked := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	for range 2 {
		user, err := ts.samlLogin(ts.A, "saml-name-id", "alice@example.com")
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), linked.ID, user.ID)
	}

	count, err := ts.API.db.Q().Where("email = ?", "alice@example.com").Count(&models.User{})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), 1, count)

	providerIDs := []string{}
	for _, identity := range ts.identities(linked) {
		require.Equal(ts.T(), "sso:"+ts.A.ID.String(), identity.Provider)
		providerIDs = append(providerIDs, identity.ProviderID)
	}
	require.ElementsMatch(ts.T(), []string{"Alice@Example.com", "saml-name-id"}, providerIDs)
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginBlockedForDivergedNameIDWhileInactive() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.setActive(id, false)
	linked := ts.linkedUser(id)

	_, err := ts.samlLogin(ts.A, "saml-name-id", "alice@example.com")
	require.Error(ts.T(), err)
	require.Len(ts.T(), ts.identities(linked), 1)
}

func (ts *SCIMUsersTestSuite) users(email string) int {
	count, err := ts.API.db.Q().Where("email = ?", email).Count(&models.User{})
	require.NoError(ts.T(), err)
	return count
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginAllowsJITWithoutSCIMToken() {
	provider := createSSOProvider(ts.T(), ts.API.db)

	user, err := ts.samlLogin(provider, "jit-user", "jit@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), "jit@example.com", user.GetEmail())
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginAllowsJITWhileSCIMFlagOff() {
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	user, err := ts.samlLogin(ts.A, "jit-user", "jit@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), "jit@example.com", user.GetEmail())
}

func (ts *SCIMUsersTestSuite) TestSAMLLoginNotBlockedByOtherProvider() {
	id := ts.create(ts.TokenB, oktaUser)
	w, _ := ts.do(ts.TokenB, http.MethodPatch, "/Users/"+id, `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "value": {"active": false}}]
	}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	existing := ts.ssoUser(ts.A, "Alice@Example.com", "alice@example.com")
	user, err := ts.samlLogin(ts.A, "Alice@Example.com", "alice@example.com")

	require.NoError(ts.T(), err)
	require.Equal(ts.T(), existing.ID, user.ID)
}

func (ts *SCIMUsersTestSuite) issueSession(conn *storage.Connection, user *models.User) error {
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	_, err := ts.API.tokenService.IssueRefreshToken(r, http.Header{}, conn, user, models.OAuth, models.GrantParams{})
	return err
}

func (ts *SCIMUsersTestSuite) requireBanned(err error) {
	var httpErr *apierrors.HTTPError
	require.True(ts.T(), errors.As(err, &httpErr), err)
	require.Equal(ts.T(), http.StatusForbidden, httpErr.HTTPStatus)
	require.Equal(ts.T(), apierrors.ErrorCodeUserBanned, httpErr.ErrorCode)
}

func (ts *SCIMUsersTestSuite) TestSessionRefusedWhileDeprovisioned() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))

	ts.setActive(id, false)
	ts.requireBanned(ts.issueSession(ts.API.db, user))
	require.Zero(ts.T(), ts.sessions(user))

	ts.setActive(id, true)
	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))

	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	ts.requireBanned(ts.issueSession(ts.API.db, user))

	relinked := ts.linkedUser(ts.create(ts.TokenA, oktaUser))
	require.Equal(ts.T(), user.ID, relinked.ID)
	require.NoError(ts.T(), ts.issueSession(ts.API.db, relinked))
}

func (ts *SCIMUsersTestSuite) TestSessionAllowedWhileSCIMFlagOff() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	ts.setActive(id, false)
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))
}

func (ts *SCIMUsersTestSuite) TestSessionRefusedForLinkedOAuthIdentityWhileDeprovisioned() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	identity, err := models.NewIdentity(user, "google", map[string]any{"sub": "google-sub", "email": "alice@example.com"})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(identity))
	ts.setActive(id, false)

	userData := &provider.UserProvidedData{
		Metadata: &provider.Claims{Subject: "google-sub", Email: "alice@example.com", EmailVerified: true},
		Emails:   []provider.Email{{Email: "alice@example.com", Primary: true, Verified: true}},
	}
	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		_, found, terr := ts.API.createAccountFromExternalIdentity(tx, httptest.NewRequest(http.MethodGet, "/callback", nil), userData, "google", false)
		if terr != nil {
			return terr
		}
		require.Equal(ts.T(), user.ID, found.ID)
		return ts.issueSession(tx, found)
	})
	ts.requireBanned(err)
	require.Zero(ts.T(), ts.sessions(user))
}

func (ts *SCIMUsersTestSuite) TestSessionWaitsForConcurrentDeactivation() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	locked, release := make(chan struct{}), make(chan struct{})
	deactivated := make(chan error, 1)
	go func() {
		deactivated <- ts.API.db.Transaction(func(tx *storage.Connection) error {
			if err := models.LockUserForSCIM(tx, user.ID); err != nil {
				return err
			}
			close(locked)
			<-release
			if err := tx.RawQuery("UPDATE "+(&models.SCIMUser{}).TableName()+" SET deleted_at = now() WHERE id = ?", id).Exec(); err != nil {
				return err
			}
			return models.Logout(tx, user.ID)
		})
	}()
	<-locked

	issued := make(chan error, 1)
	go func() { issued <- ts.issueSession(ts.API.db, user) }()
	select {
	case err := <-issued:
		ts.T().Fatalf("session issued while deactivation held the user lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)

	require.NoError(ts.T(), <-deactivated)
	ts.requireBanned(<-issued)
	require.Zero(ts.T(), ts.sessions(user))
}

func (ts *SCIMUsersTestSuite) TestWritesWaitForAdminUserDelete() {
	for _, method := range []string{http.MethodDelete, http.MethodPut} {
		body := userWith(strings.ToLower(method)+"@example.com", method)
		id := ts.create(ts.TokenA, body)
		user := ts.linkedUser(id)
		code, err := ts.whileLocked(
			func(tx *storage.Connection) error { return models.LockUserForSCIM(tx, user.ID) },
			func(tx *storage.Connection) error {
				_, err := models.SoftDeleteSCIMUsersByUserID(tx, user.ID)
				return err
			},
			method, "/Users/"+id, body,
		)
		require.NoError(ts.T(), err, method)
		require.Equal(ts.T(), http.StatusNotFound, code, method)
	}
}

func (ts *SCIMUsersTestSuite) TestSessionAllowedForSSOUserWithoutSCIMRow() {
	user := ts.ssoUser(ts.A, "saml-sub", "carol@example.com")
	require.NoError(ts.T(), ts.issueSession(ts.API.db, user))
}

func (ts *SCIMUsersTestSuite) setActive(id string, active bool) {
	ts.setActiveAs(ts.TokenA, id, active)
}

func (ts *SCIMUsersTestSuite) setActiveAs(token, id string, active bool) {
	w, _ := ts.do(token, http.MethodPatch, "/Users/"+id, `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "value": {"active": `+strconv.FormatBool(active)+`}}]
	}`)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
}

func (ts *SCIMUsersTestSuite) TestReplaceDeactivatesAndReactivates() {
	id := ts.create(ts.TokenA, oktaUser)
	require.Equal(ts.T(), http.StatusOK, ts.refresh(ts.refreshToken(ts.linkedUser(id))))
	refreshToken := ts.refreshToken(ts.linkedUser(id))

	ts.setActive(id, false)
	user := ts.linkedUser(id)
	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
	require.Equal(ts.T(), http.StatusBadRequest, ts.refresh(refreshToken))

	listed := ts.list(ts.TokenA, "")
	require.EqualValues(ts.T(), 1, listed["totalResults"])
	require.Equal(ts.T(), id, listed["Resources"].([]any)[0].(map[string]any)["id"])
	require.Equal(ts.T(), false, listed["Resources"].([]any)[0].(map[string]any)["active"])

	ts.setActive(id, true)
	require.False(ts.T(), ts.linkedUser(id).IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
	require.Equal(ts.T(), http.StatusBadRequest, ts.refresh(refreshToken))
}

func (ts *SCIMUsersTestSuite) TestPutInactiveRevokesSessions() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	refreshToken := ts.refreshToken(user)

	w, got := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, strings.Replace(oktaUser, `"active": true`, `"active": false`, 1))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Equal(ts.T(), false, got["active"])
	require.Zero(ts.T(), ts.sessions(user))
	require.Equal(ts.T(), http.StatusBadRequest, ts.refresh(refreshToken))
	require.Len(ts.T(), ts.auditActions(models.SCIMUserDeactivatedAction), 1)
}

func (ts *SCIMUsersTestSuite) TestReplaceKeepsAdminBanWhenActiveDoesNotChange() {
	id := ts.create(ts.TokenA, oktaUser)
	require.NoError(ts.T(), ts.linkedUser(id).Ban(ts.API.db, time.Hour))

	ts.setActive(id, true)
	require.True(ts.T(), ts.linkedUser(id).IsBanned())
}

func (ts *SCIMUsersTestSuite) TestReplaceLinksUnlinkedRow() {
	row, err := models.CreateSCIMUser(ts.API.db, ts.A.ID, []byte(`{"userName":"Alice@Example.com"}`))
	require.NoError(ts.T(), err)

	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+row.ID.String(), strings.Replace(oktaUser, `"active": true`, `"active": false`, 1))
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	user := ts.linkedUser(row.ID.String())
	require.Equal(ts.T(), "alice@example.com", user.GetEmail())
	require.False(ts.T(), user.IsBanned())
}

func (ts *SCIMUsersTestSuite) TestDeleteLogsOutWithoutBanning() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	refreshToken := ts.refreshToken(user)

	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	user, err := models.FindUserByID(ts.API.db, user.ID)
	require.NoError(ts.T(), err)
	require.False(ts.T(), user.IsBanned())
	require.Zero(ts.T(), ts.sessions(user))
	require.Equal(ts.T(), http.StatusBadRequest, ts.refresh(refreshToken))
}

func (ts *SCIMUsersTestSuite) TestCreateDoesNotBanAfterDelete() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	relinked := ts.linkedUser(ts.create(ts.TokenA, oktaUser))

	require.Equal(ts.T(), user.ID, relinked.ID)
	require.False(ts.T(), relinked.IsBanned())
}

func (ts *SCIMUsersTestSuite) TestCreateConcurrentSameEmailLinksToOneUser() {
	body := func(userName, externalID string) string {
		return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + userName + `","externalId":"` + externalID + `","emails":[{"primary":true,"value":"race@example.com"}]}`
	}
	bodies := []string{body("race-a", "race-a"), body("race-b", "race-b")}

	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, len(bodies))
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(bodies[i]))
			r.Header.Set("Authorization", "Bearer "+ts.TokenA)
			r.Header.Set("Content-Type", protocol.MediaType)
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, r)
			codes[i] = w.Code
		}(i)
	}
	close(start)
	wg.Wait()

	// The lock serializes the two creates: whichever commits first creates the
	// user, the other observes that account under the same provider and is
	// rejected as already linked -- never silently creating a second user.
	created := 0
	for _, code := range codes {
		if code == http.StatusCreated {
			created++
		} else {
			require.Equal(ts.T(), http.StatusConflict, code)
		}
	}
	require.Equal(ts.T(), 1, created)

	count, err := ts.API.db.Q().Where("email = ?", "race@example.com").Count(&models.User{})
	require.NoError(ts.T(), err)
	require.EqualValues(ts.T(), 1, count)
}

func (ts *SCIMUsersTestSuite) rename(id, userName string) (int, string) {
	w, _ := ts.do(ts.TokenA, http.MethodPut, "/Users/"+id, strings.Replace(oktaUser, `"userName": "Alice@Example.com"`, `"userName": "`+userName+`"`, 1))
	return w.Code, w.Body.String()
}

func (ts *SCIMUsersTestSuite) TestReplaceRenamesSSOIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)

	code, body := ts.rename(id, "alice2@example.com")
	require.Equal(ts.T(), http.StatusOK, code, body)

	identity, err := models.FindIdentityByIdAndProvider(ts.API.db, "alice2@example.com", "sso:"+ts.A.ID.String())
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), user.ID, identity.UserID)
	require.Equal(ts.T(), "alice2@example.com", identity.IdentityData["sub"])
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMUsersTestSuite) providerIDs(user *models.User) []string {
	ids := []string{}
	for _, identity := range ts.identities(user) {
		ids = append(ids, identity.ProviderID)
	}
	return ids
}

func (ts *SCIMUsersTestSuite) TestReplaceRenamesCaseOnly() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	_, err := ts.samlLogin(ts.A, "alice@example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.ElementsMatch(ts.T(), []string{"Alice@Example.com", "alice@example.com"}, ts.providerIDs(user))

	for range 2 {
		code, body := ts.rename(id, "alice@example.com")
		require.Equal(ts.T(), http.StatusOK, code, body)
	}
	require.Equal(ts.T(), []string{"alice@example.com"}, ts.providerIDs(user))

	signedIn, err := ts.samlLogin(ts.A, "alice@example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), user.ID, signedIn.ID)
}

func (ts *SCIMUsersTestSuite) TestReplaceRenameRemovesOldNameIDIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	_, err := ts.samlLogin(ts.A, "alice@example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	_, err = ts.samlLogin(ts.A, "saml-name-id", "alice@example.com")
	require.NoError(ts.T(), err)

	code, body := ts.rename(id, "bob@example.com")
	require.Equal(ts.T(), http.StatusOK, code, body)
	require.ElementsMatch(ts.T(), []string{"bob@example.com", "saml-name-id"}, ts.providerIDs(user))

	signedIn, err := ts.samlLogin(ts.A, "alice@example.com", "new-hire@example.com")
	require.NoError(ts.T(), err)
	require.NotEqual(ts.T(), user.ID, signedIn.ID)
}

func (ts *SCIMUsersTestSuite) TestReplaceRejectsRenameToTakenIdentity() {
	id := ts.create(ts.TokenA, oktaUser)
	ts.ssoUser(ts.A, "bob@example.com", "bob@example.com")

	code, body := ts.rename(id, "bob@example.com")
	require.Equal(ts.T(), http.StatusConflict, code, body)

	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))
	require.Equal(ts.T(), "alice@example.com", row.UserName)
	_, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", "sso:"+ts.A.ID.String())
	require.NoError(ts.T(), err)
}

func (ts *SCIMUsersTestSuite) unlink(user *models.User, identity *models.Identity) *httptest.ResponseRecorder {
	session, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))
	token, _, err := ts.API.generateAccessToken(httptest.NewRequest(http.MethodPost, "/token", nil), ts.API.db, user, &session.ID, models.PasswordGrant)
	require.NoError(ts.T(), err)
	r := httptest.NewRequest(http.MethodDelete, "/user/identities/"+identity.ID.String(), nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, r)
	return w
}

func (ts *SCIMUsersTestSuite) TestUnlinkRefusedForSCIMManagedIdentity() {
	ts.API.config.Security.ManualLinkingEnabled = true
	defer func() { ts.API.config.Security.ManualLinkingEnabled = false }()
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	google, err := models.NewIdentity(user, "google", map[string]any{"sub": "google-1", "email": "alice@example.com"})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(google))
	sso, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", "sso:"+ts.A.ID.String())
	require.NoError(ts.T(), err)

	w := ts.unlink(user, sso)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code, w.Body.String())
	require.Contains(ts.T(), w.Body.String(), string(apierrors.ErrorCodeUserSSOManaged))
	require.Len(ts.T(), ts.identities(user), 2)

	code, body := ts.rename(id, "alice2@example.com")
	require.Equal(ts.T(), http.StatusOK, code, body)
	sso, err = models.FindIdentityByIdAndProvider(ts.API.db, "alice2@example.com", "sso:"+ts.A.ID.String())
	require.NoError(ts.T(), err)

	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Users/"+id, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	w = ts.unlink(user, sso)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMUsersTestSuite) TestUnlinkAllowedWhileSCIMFlagOff() {
	ts.API.config.Security.ManualLinkingEnabled = true
	defer func() { ts.API.config.Security.ManualLinkingEnabled = false }()
	user := ts.linkedUser(ts.create(ts.TokenA, oktaUser))
	google, err := models.NewIdentity(user, "google", map[string]any{"sub": "google-1", "email": "alice@example.com"})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(google))
	sso, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", "sso:"+ts.A.ID.String())
	require.NoError(ts.T(), err)
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	w := ts.unlink(user, sso)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	require.Len(ts.T(), ts.identities(user), 1)
}

func (ts *SCIMUsersTestSuite) TestRenameSkippedWhenIdentityMissing() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	sso, err := models.FindIdentityByIdAndProvider(ts.API.db, "Alice@Example.com", "sso:"+ts.A.ID.String())
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Destroy(sso))
	before := len(ts.scimAuditEntries())
	hook := logrustest.NewGlobal()
	defer hook.Reset()

	code, body := ts.rename(id, "alice2@example.com")
	require.Equal(ts.T(), http.StatusOK, code, body)

	var row models.SCIMUser
	require.NoError(ts.T(), ts.API.db.Q().Where("id = ?", id).First(&row))
	require.Equal(ts.T(), "alice2@example.com", row.UserName)
	require.Empty(ts.T(), ts.identities(user))
	entries := ts.scimAuditEntries()[before:]
	require.Len(ts.T(), entries, 1)
	require.Equal(ts.T(), string(models.SCIMUserUpdatedAction), entries[0].Payload["action"])
	warned := false
	for _, entry := range hook.AllEntries() {
		warned = warned || entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "SCIM identity")
	}
	require.True(ts.T(), warned)

	signedIn, err := ts.samlLogin(ts.A, "alice2@example.com", "alice@example.com")
	require.NoError(ts.T(), err)
	require.NotEqual(ts.T(), user.ID, signedIn.ID)
	require.Equal(ts.T(), 2, ts.users("alice@example.com"))
}
