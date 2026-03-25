package admin

import (
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"github.com/ryanbekhen/nanoproxy/pkg/traffic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_LoginAndUserManagement(t *testing.T) {
	logger := zerolog.New(io.Discard)
	credentials := credential.NewStaticCredentialStore()
	userStore := credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db"))

	s := New(&Config{
		Credentials:   credentials,
		UserStore:     userStore,
		AdminUsername: "admin",
		AdminPassword: "secret",
		Logger:        &logger,
	})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)

	client := &http.Client{Jar: jar}

	resp, err := client.Get(ts.URL + "/")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/admin/login", resp.Request.URL.Path)
	_ = resp.Body.Close()

	resp, err = client.Get(ts.URL + "/admin/users")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/admin/login", resp.Request.URL.Path)
	_ = resp.Body.Close()

	resp, err = client.PostForm(ts.URL+"/admin/login", url.Values{
		"username": {"admin"},
		"password": {"wrong"},
	})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()

	resp, err = client.PostForm(ts.URL+"/admin/login", url.Values{
		"username": {"admin"},
		"password": {"secret"},
	})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/admin/users", resp.Request.URL.Path)
	_ = resp.Body.Close()

	resp, err = client.Get(ts.URL + "/admin/users")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	_ = resp.Body.Close()

	csrfToken := extractCSRFToken(t, string(body))

	resp, err = client.PostForm(ts.URL+"/admin/users", url.Values{"username": {"proxyuser"}, "_csrf": {csrfToken}})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	_ = resp.Body.Close()
	csrfToken = extractCSRFToken(t, string(body))

	createdPassword := extractGeneratedPassword(t, string(body))
	assert.NotEmpty(t, createdPassword)

	assert.True(t, credentials.Valid("proxyuser", createdPassword))

	restartedStore := credential.NewStaticCredentialStore()
	assert.NoError(t, credential.LoadInto(userStore, restartedStore))
	assert.True(t, restartedStore.Valid("proxyuser", createdPassword))

	resp, err = client.PostForm(ts.URL+"/admin/users", url.Values{
		"username": {"proxyuser"},
		"_csrf":    {csrfToken},
	})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	_ = resp.Body.Close()
	csrfToken = extractCSRFToken(t, string(body))

	resp, err = client.PostForm(ts.URL+"/admin/users/proxyuser/reset-password", url.Values{"_csrf": {csrfToken}})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	_ = resp.Body.Close()
	csrfToken = extractCSRFToken(t, string(body))

	resetPassword := extractGeneratedPassword(t, string(body))
	assert.NotEmpty(t, resetPassword)
	assert.NotEqual(t, createdPassword, resetPassword)
	assert.False(t, credentials.Valid("proxyuser", createdPassword))
	assert.True(t, credentials.Valid("proxyuser", resetPassword))
	assert.NoError(t, credential.LoadInto(userStore, restartedStore))
	assert.True(t, restartedStore.Valid("proxyuser", resetPassword))

	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/admin/users/proxyuser", nil)
	assert.NoError(t, err)
	req.Header.Set("X-CSRF-Token", csrfToken)
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	assert.False(t, credentials.Valid("proxyuser", resetPassword))
	assert.NoError(t, credential.LoadInto(userStore, restartedStore))
	assert.False(t, restartedStore.Valid("proxyuser", resetPassword))
}

func TestValidateUsername(t *testing.T) {
	assert.Error(t, validateUsername(""))
	assert.Error(t, validateUsername("ab"))
	assert.Error(t, validateUsername("foo:bar"))
	assert.Error(t, validateUsername("bad user"))
	assert.Error(t, validateUsername("bad/user"))
	assert.Error(t, validateUsername(strings.Repeat("a", 65)))
	assert.NoError(t, validateUsername("foo"))
	assert.NoError(t, validateUsername("user.name-01"))
}

func TestServer_LoginRequiresConfiguredCredentials(t *testing.T) {
	logger := zerolog.New(io.Discard)
	credentials := credential.NewStaticCredentialStore()

	s := New(&Config{
		Credentials:   credentials,
		UserStore:     credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername: "admin",
		AdminPassword: "secret",
		Logger:        &logger,
	})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/admin/login", "application/x-www-form-urlencoded", strings.NewReader("username=bad&password=bad"))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestGeneratePassword(t *testing.T) {
	password, err := generatePassword(20)
	assert.NoError(t, err)
	assert.Len(t, password, 20)

	_, err = generatePassword(0)
	assert.Error(t, err)
}

func TestServer_CreateUserRejectsInvalidUsername(t *testing.T) {
	logger := zerolog.New(io.Discard)
	credentials := credential.NewStaticCredentialStore()

	s := New(&Config{
		Credentials:   credentials,
		UserStore:     credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername: "admin",
		AdminPassword: "secret",
		Logger:        &logger,
	})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)
	client := &http.Client{Jar: jar}

	resp, err := client.PostForm(ts.URL+"/admin/login", url.Values{
		"username": {"admin"},
		"password": {"secret"},
	})
	assert.NoError(t, err)
	_ = resp.Body.Close()

	resp, err = client.Get(ts.URL + "/admin/users")
	assert.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	_ = resp.Body.Close()

	csrfToken := extractCSRFToken(t, string(body))

	resp, err = client.PostForm(ts.URL+"/admin/users", url.Values{"username": {"bad user"}, "_csrf": {csrfToken}})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	_ = resp.Body.Close()

	assert.Contains(t, string(body), "username may only contain letters, numbers, dots, underscores, and hyphens")
	assert.False(t, credentials.Exists("bad user"))
}

func TestServer_StateChangingRoutesRequireCSRF(t *testing.T) {
	logger := zerolog.New(io.Discard)
	credentials := credential.NewStaticCredentialStore()

	s := New(&Config{
		Credentials:   credentials,
		UserStore:     credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername: "admin",
		AdminPassword: "secret",
		Logger:        &logger,
	})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)
	client := &http.Client{Jar: jar}

	resp, err := client.PostForm(ts.URL+"/admin/login", url.Values{"username": {"admin"}, "password": {"secret"}})
	assert.NoError(t, err)
	_ = resp.Body.Close()

	resp, err = client.PostForm(ts.URL+"/admin/users", url.Values{"username": {"proxyuser"}})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_CSRFTokenRotationRejectsOldToken(t *testing.T) {
	logger := zerolog.New(io.Discard)
	credentials := credential.NewStaticCredentialStore()

	s := New(&Config{
		Credentials:   credentials,
		UserStore:     credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername: "admin",
		AdminPassword: "secret",
		Logger:        &logger,
	})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	assert.NoError(t, err)
	client := &http.Client{Jar: jar}

	resp, err := client.PostForm(ts.URL+"/admin/login", url.Values{"username": {"admin"}, "password": {"secret"}})
	assert.NoError(t, err)
	_ = resp.Body.Close()

	resp, err = client.Get(ts.URL + "/admin/users")
	assert.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	_ = resp.Body.Close()

	firstToken := extractCSRFToken(t, string(body))

	resp, err = client.PostForm(ts.URL+"/admin/users", url.Values{"username": {"userone"}, "_csrf": {firstToken}})
	assert.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	assert.NoError(t, err)
	_ = resp.Body.Close()

	rotatedToken := extractCSRFToken(t, string(body))
	assert.NotEqual(t, firstToken, rotatedToken)

	resp, err = client.PostForm(ts.URL+"/admin/users", url.Values{"username": {"usertwo"}, "_csrf": {firstToken}})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_OriginPolicy(t *testing.T) {
	logger := zerolog.New(io.Discard)
	credentials := credential.NewStaticCredentialStore()

	s := New(&Config{
		Credentials:    credentials,
		UserStore:      credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername:  "admin",
		AdminPassword:  "secret",
		AllowedOrigins: []string{"http://allowed.local"},
		Logger:         &logger,
	})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/admin/login", "application/x-www-form-urlencoded", strings.NewReader("username=admin&password=secret"))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/admin/login", strings.NewReader("username=admin&password=secret"))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://allowed.local")

	client := &http.Client{}
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.NotEqual(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()
}

// loginHelper logs the given admin in and returns a client with a valid session
// plus the current CSRF token extracted from /admin/users.
func loginHelper(t *testing.T, baseURL string) (*http.Client, string) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	resp, err := client.PostForm(baseURL+"/admin/login", url.Values{
		"username": {"admin"},
		"password": {"secret"},
	})
	require.NoError(t, err)
	_ = resp.Body.Close()

	resp, err = client.Get(baseURL + "/admin/users")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	return client, extractCSRFToken(t, string(body))
}

// newAdminServer creates a Server with an in-memory credential store and a temp-dir BoltDB store.
func newAdminServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	creds := credential.NewStaticCredentialStore()
	s := New(&Config{
		Credentials:   creds,
		UserStore:     credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername: "admin",
		AdminPassword: "secret",
		Logger:        &logger,
	})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func TestServer_NilLogger(t *testing.T) {
	creds := credential.NewStaticCredentialStore()
	s := New(&Config{
		Credentials:   creds,
		UserStore:     credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername: "admin",
		AdminPassword: "secret",
		// Logger intentionally nil — default logger must be created
	})
	assert.NotNil(t, s)
	assert.NotNil(t, s.config.Logger)
}

func TestServer_Root_NotFound(t *testing.T) {
	_, ts := newAdminServer(t)

	resp, err := http.Get(ts.URL + "/does-not-exist")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_Root_Redirect(t *testing.T) {
	_, ts := newAdminServer(t)

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := noFollow.Get(ts.URL + "/")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/admin", resp.Header.Get("Location"))
	_ = resp.Body.Close()
}

func TestServer_Index_Unauthenticated(t *testing.T) {
	_, ts := newAdminServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, err := client.Get(ts.URL + "/admin")
	assert.NoError(t, err)
	assert.Equal(t, "/admin/login", resp.Request.URL.Path)
	_ = resp.Body.Close()
}

func TestServer_Index_Authenticated(t *testing.T) {
	_, ts := newAdminServer(t)
	client, _ := loginHelper(t, ts.URL)

	noFollow := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noFollow.Get(ts.URL + "/admin")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/admin/users", resp.Header.Get("Location"))
	_ = resp.Body.Close()
}

func TestServer_LoginPage_GetShowsForm(t *testing.T) {
	_, ts := newAdminServer(t)

	resp, err := http.Get(ts.URL + "/admin/login")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_LoginPage_GetRedirectsWhenAuthenticated(t *testing.T) {
	_, ts := newAdminServer(t)
	client, _ := loginHelper(t, ts.URL)

	noFollow := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noFollow.Get(ts.URL + "/admin/login")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/admin/users", resp.Header.Get("Location"))
	_ = resp.Body.Close()
}

func TestServer_Login_MethodNotAllowed(t *testing.T) {
	_, ts := newAdminServer(t)

	req, err := http.NewRequest(http.MethodPut, ts.URL+"/admin/login", nil)
	assert.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_Logout_MethodNotAllowed(t *testing.T) {
	_, ts := newAdminServer(t)

	resp, err := http.Get(ts.URL + "/admin/logout")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_Logout_InvalidCSRF(t *testing.T) {
	_, ts := newAdminServer(t)

	resp, err := http.Post(ts.URL+"/admin/logout", "application/x-www-form-urlencoded",
		strings.NewReader("_csrf=bad-token"))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_Logout_Valid(t *testing.T) {
	_, ts := newAdminServer(t)
	client, csrfToken := loginHelper(t, ts.URL)

	// POST logout with valid CSRF token
	resp, err := client.PostForm(ts.URL+"/admin/logout", url.Values{"_csrf": {csrfToken}})
	assert.NoError(t, err)
	assert.Equal(t, "/admin/login", resp.Request.URL.Path)
	_ = resp.Body.Close()

	// After logout, /admin/users must redirect to login
	resp, err = client.Get(ts.URL + "/admin/users")
	assert.NoError(t, err)
	assert.Equal(t, "/admin/login", resp.Request.URL.Path)
	_ = resp.Body.Close()
}

func TestServer_RateLimiting(t *testing.T) {
	logger := zerolog.New(io.Discard)
	creds := credential.NewStaticCredentialStore()
	s := New(&Config{
		Credentials:      creds,
		UserStore:        credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername:    "admin",
		AdminPassword:    "secret",
		MaxLoginAttempts: 3,
		LoginWindow:      time.Minute,
		LockoutDuration:  50 * time.Millisecond,
		Logger:           &logger,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// Exhaust the login attempts
	for i := 0; i < 3; i++ {
		resp, err := http.Post(ts.URL+"/admin/login", "application/x-www-form-urlencoded",
			strings.NewReader("username=admin&password=wrong"))
		assert.NoError(t, err)
		_ = resp.Body.Close()
	}

	// Next attempt must be rejected with 429
	resp, err := http.Post(ts.URL+"/admin/login", "application/x-www-form-urlencoded",
		strings.NewReader("username=admin&password=secret"))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	_ = resp.Body.Close()

	// Wait for lockout to expire
	time.Sleep(100 * time.Millisecond)

	// Now a valid login should succeed again
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err = client.PostForm(ts.URL+"/admin/login", url.Values{
		"username": {"admin"},
		"password": {"secret"},
	})
	assert.NoError(t, err)
	assert.Equal(t, "/admin/users", resp.Request.URL.Path)
	_ = resp.Body.Close()
}

func TestServer_Users_MethodNotAllowed(t *testing.T) {
	_, ts := newAdminServer(t)
	client, _ := loginHelper(t, ts.URL)

	req, err := http.NewRequest(http.MethodPut, ts.URL+"/admin/users", nil)
	assert.NoError(t, err)
	resp, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_UserByName_EmptyUsername(t *testing.T) {
	_, ts := newAdminServer(t)
	client, _ := loginHelper(t, ts.URL)

	resp, err := client.Get(ts.URL + "/admin/users/")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_UserByName_MethodNotAllowed(t *testing.T) {
	_, ts := newAdminServer(t)
	client, _ := loginHelper(t, ts.URL)

	resp, err := client.Get(ts.URL + "/admin/users/someuser")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_UserByName_UnauthenticatedRedirectsToLogin(t *testing.T) {
	_, ts := newAdminServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, err := client.Get(ts.URL + "/admin/users/anyuser")
	assert.NoError(t, err)
	assert.Equal(t, "/admin/login", resp.Request.URL.Path)
	_ = resp.Body.Close()
}

func TestServer_UserRows_UnauthenticatedHTMXRedirectsToLogin(t *testing.T) {
	_, ts := newAdminServer(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/admin/users/rows", nil)
	require.NoError(t, err)
	req.Header.Set("HX-Request", "true")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "/admin/login", resp.Header.Get("HX-Redirect"))
}

func TestServer_ResetPassword_UserNotFound(t *testing.T) {
	_, ts := newAdminServer(t)
	client, csrfToken := loginHelper(t, ts.URL)

	resp, err := client.PostForm(ts.URL+"/admin/users/nonexistent/reset-password",
		url.Values{"_csrf": {csrfToken}})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_ProxyUsersWithTraffic_RecentSessionStillActive(t *testing.T) {
	logger := zerolog.New(io.Discard)
	creds := credential.NewStaticCredentialStore()
	creds.Add("alice", "password")

	tracker := traffic.NewTracker()
	sess := tracker.Start("alice", "10.0.0.2")
	sess.AddUpload(256)
	sess.AddDownload(512)
	sess.Close()

	s := New(&Config{
		Credentials:   creds,
		Tracker:       tracker,
		AdminUsername: "admin",
		AdminPassword: "secret",
		Logger:        &logger,
	})

	rows := s.proxyUsersWithTraffic()
	require.Len(t, rows, 1)
	assert.Equal(t, "alice", rows[0].Username)
	assert.Equal(t, "Active", rows[0].Status)
	assert.Equal(t, 0, rows[0].ActiveClients)
	assert.Equal(t, "10.0.0.2", rows[0].ClientIP)
	assert.NotEqual(t, "0 B", rows[0].DownloadTotal)
	assert.NotEqual(t, "0 B", rows[0].UploadTotal)
}

func TestServer_NilUserStore_CreateUser(t *testing.T) {
	logger := zerolog.New(io.Discard)
	creds := credential.NewStaticCredentialStore()
	s := New(&Config{
		Credentials:   creds,
		UserStore:     nil, // nil — persistUsers must short-circuit
		AdminUsername: "admin",
		AdminPassword: "secret",
		Logger:        &logger,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	client, csrf := loginHelper(t, ts.URL)

	resp, err := client.PostForm(ts.URL+"/admin/users",
		url.Values{"username": {"newuser"}, "_csrf": {csrf}})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	assert.True(t, creds.Exists("newuser"))
}

func TestServer_SessionExpired(t *testing.T) {
	s, ts := newAdminServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, err := client.PostForm(ts.URL+"/admin/login", url.Values{
		"username": {"admin"},
		"password": {"secret"},
	})
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Expire every session manually
	s.mu.Lock()
	for k, v := range s.sessions {
		v.ExpiresAt = time.Now().Add(-time.Hour)
		s.sessions[k] = v
	}
	s.mu.Unlock()

	// After expiry, /admin/users must redirect to login
	resp, err = client.Get(ts.URL + "/admin/users")
	assert.NoError(t, err)
	assert.Equal(t, "/admin/login", resp.Request.URL.Path)
	_ = resp.Body.Close()
}

func TestServer_SessionInvalidToken(t *testing.T) {
	_, ts := newAdminServer(t)

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "token-that-does-not-exist"})
	resp, err := noFollow.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestNormalizeOrigin_NoScheme(t *testing.T) {
	_, err := normalizeOrigin("no-scheme")
	assert.Error(t, err)
}

func TestNormalizeOrigin_NoHost(t *testing.T) {
	_, err := normalizeOrigin("http://")
	assert.Error(t, err)
}

func TestNormalizeAllowedOrigins_InvalidEntry(t *testing.T) {
	result := normalizeAllowedOrigins([]string{"bad-origin", "http://valid.com"})
	assert.Equal(t, []string{"http://valid.com"}, result)
}

func TestNormalizeAllowedOrigins_DuplicateEntry(t *testing.T) {
	result := normalizeAllowedOrigins([]string{"http://x.com", "http://x.com", "http://y.com"})
	assert.Equal(t, []string{"http://x.com", "http://y.com"}, result)
}

func TestExtractClientIP_NoPort(t *testing.T) {
	ip := extractClientIP("192.168.1.1")
	assert.Equal(t, "192.168.1.1", ip)
}

func TestServer_OriginPolicy_InvalidOriginHeader(t *testing.T) {
	logger := zerolog.New(io.Discard)
	creds := credential.NewStaticCredentialStore()
	s := New(&Config{
		Credentials:    creds,
		UserStore:      credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername:  "admin",
		AdminPassword:  "secret",
		AllowedOrigins: []string{"http://allowed.local"},
		Logger:         &logger,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/login",
		strings.NewReader("username=admin&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "://bad-origin") // malformed
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_OriginPolicy_WrongOrigin(t *testing.T) {
	logger := zerolog.New(io.Discard)
	creds := credential.NewStaticCredentialStore()
	s := New(&Config{
		Credentials:    creds,
		UserStore:      credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername:  "admin",
		AdminPassword:  "secret",
		AllowedOrigins: []string{"http://allowed.local"},
		Logger:         &logger,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/login",
		strings.NewReader("username=admin&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil.com")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_OriginPolicy_RefererAllowed(t *testing.T) {
	logger := zerolog.New(io.Discard)
	creds := credential.NewStaticCredentialStore()
	s := New(&Config{
		Credentials:    creds,
		UserStore:      credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername:  "admin",
		AdminPassword:  "secret",
		AllowedOrigins: []string{"http://allowed.local"},
		Logger:         &logger,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/login",
		strings.NewReader("username=admin&password=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "http://allowed.local/admin/login")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	// wrong password → 401, but origin was accepted (not 403)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_OriginPolicy_RefererNotAllowed(t *testing.T) {
	logger := zerolog.New(io.Discard)
	creds := credential.NewStaticCredentialStore()
	s := New(&Config{
		Credentials:    creds,
		UserStore:      credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername:  "admin",
		AdminPassword:  "secret",
		AllowedOrigins: []string{"http://allowed.local"},
		Logger:         &logger,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/login",
		strings.NewReader("username=admin&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "http://evil.com/path")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServer_OriginPolicy_BadReferer(t *testing.T) {
	logger := zerolog.New(io.Discard)
	creds := credential.NewStaticCredentialStore()
	s := New(&Config{
		Credentials:    creds,
		UserStore:      credential.NewBoltStore(filepath.Join(t.TempDir(), "data.db")),
		AdminUsername:  "admin",
		AdminPassword:  "secret",
		AllowedOrigins: []string{"http://allowed.local"},
		Logger:         &logger,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/login",
		strings.NewReader("username=admin&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "not-a-url-no-scheme")
	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	_ = resp.Body.Close()
}

func extractGeneratedPassword(t *testing.T, content string) string {
	t.Helper()

	re := regexp.MustCompile(`<code id="generated-password-value"[^>]*>([^<]+)</code>`)
	matches := re.FindStringSubmatch(content)
	if len(matches) != 2 {
		t.Fatalf("generated password not found in response: %s", content)
	}

	return html.UnescapeString(matches[1])
}

func extractCSRFToken(t *testing.T, content string) string {
	t.Helper()

	re := regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)">`)
	matches := re.FindStringSubmatch(content)
	if len(matches) != 2 {
		t.Fatalf("csrf token not found in response: %s", content)
	}

	return matches[1]
}
