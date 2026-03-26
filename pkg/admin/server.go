package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"github.com/ryanbekhen/nanoproxy/pkg/traffic"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*.gohtml
var templatesFS embed.FS

const (
	sessionCookieName       = "nanoproxy_admin_session"
	sessionTTL              = 12 * time.Hour
	offlineInactivityWindow = 10 * time.Minute
	statusActive            = "Active"
	statusOffline           = "Offline"
	minUsernameLength       = 3
	maxUsernameLength       = 64
	defaultMaxLoginAttempts = 5
	defaultLoginWindow      = 5 * time.Minute
	defaultLockoutDuration  = 10 * time.Minute
	minAdminPasswordLength  = 8
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

type Config struct {
	Credentials      *credential.StaticCredentialStore
	UserStore        credential.PersistentStore
	AdminStore       AdminCredentialStore
	TrafficStore     traffic.Store
	Tracker          *traffic.Tracker
	CookieSecure     bool
	MaxLoginAttempts int
	LoginWindow      time.Duration
	LockoutDuration  time.Duration
	AllowedOrigins   []string
	Logger           *zerolog.Logger
}

type Server struct {
	config   *Config
	tmpl     *template.Template
	sessions map[string]session
	logins   map[string]loginAttempt
	admin    adminCredential
	mu       sync.Mutex
}

type adminCredential struct {
	Username     string
	PasswordHash string
}

type session struct {
	ExpiresAt time.Time
	CSRFToken string
}

type loginAttempt struct {
	Count       int
	FirstFailed time.Time
	LockedUntil time.Time
}

type usersViewData struct {
	Error             string
	Success           string
	GeneratedUsername string
	GeneratedPassword string
	CSRFToken         string
	ProxyUsers        []proxyUserView
	TotalUsers        int
}

type setupViewData struct {
	Error string
}

type proxyUserView struct {
	Username      string
	ActiveClients int
	ClientIP      string
	UploadRate    string
	DownloadRate  string
	UploadTotal   string
	DownloadTotal string
	Status        string
	StartedAgo    string
}

func New(conf *Config) *Server {
	if conf.Logger == nil {
		logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger()
		conf.Logger = &logger
	}

	if conf.MaxLoginAttempts <= 0 {
		conf.MaxLoginAttempts = defaultMaxLoginAttempts
	}

	if conf.LoginWindow <= 0 {
		conf.LoginWindow = defaultLoginWindow
	}

	if conf.LockoutDuration <= 0 {
		conf.LockoutDuration = defaultLockoutDuration
	}

	if conf.Credentials == nil {
		conf.Credentials = credential.NewStaticCredentialStore()
	}

	conf.AllowedOrigins = normalizeAllowedOrigins(conf.AllowedOrigins)

	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.gohtml"))

	server := &Server{
		config:   conf,
		tmpl:     tmpl,
		sessions: make(map[string]session),
		logins:   make(map[string]loginAttempt),
	}

	if conf.AdminStore != nil {
		username, passwordHash, found, err := conf.AdminStore.Load()
		if err != nil {
			conf.Logger.Warn().Err(err).Msg("failed to load admin credentials from store")
		} else if found {
			server.admin = adminCredential{Username: username, PasswordHash: passwordHash}
		}
	}

	return server
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/admin", s.handleIndex)
	mux.HandleFunc("/admin/setup", s.handleSetup)
	mux.HandleFunc("/admin/login", s.handleLogin)
	mux.HandleFunc("/admin/logout", s.handleLogout)
	mux.HandleFunc("/admin/users", s.handleUsers)
	mux.HandleFunc("/admin/users/rows", s.handleUserRows)
	mux.HandleFunc("/admin/users/", s.handleUserByName)
	return s.withSecurityHeaders(mux)
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if !s.hasConfiguredAdminCredentials() {
		http.Redirect(w, r, "/admin/setup", http.StatusSeeOther)
		return
	}

	if s.isAuthenticated(r) {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.hasConfiguredAdminCredentials() {
		if s.isAuthenticated(r) {
			http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.renderTemplate(w, "setup.gohtml", setupViewData{}, http.StatusOK)
	case http.MethodPost:
		// Check again if admin already configured (prevent double setup)
		if s.hasConfiguredAdminCredentials() {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}

		if err := s.verifyOrigin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		if err := validateUsername(username); err != nil {
			s.renderTemplate(w, "setup.gohtml", setupViewData{Error: err.Error()}, http.StatusBadRequest)
			return
		}

		if len(password) < minAdminPasswordLength {
			s.renderTemplate(w, "setup.gohtml", setupViewData{Error: fmt.Sprintf("password must be at least %d characters", minAdminPasswordLength)}, http.StatusBadRequest)
			return
		}

		if subtle.ConstantTimeCompare([]byte(password), []byte(confirmPassword)) != 1 {
			s.renderTemplate(w, "setup.gohtml", setupViewData{Error: "password confirmation does not match"}, http.StatusBadRequest)
			return
		}

		if err := s.bootstrapAdminCredentials(username, password); err != nil {
			if strings.Contains(err.Error(), "already configured") {
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}
			s.renderTemplate(w, "setup.gohtml", setupViewData{Error: "failed to create admin credentials"}, http.StatusInternalServerError)
			return
		}

		if err := s.createSession(w); err != nil {
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.hasConfiguredAdminCredentials() {
			http.Redirect(w, r, "/admin/setup", http.StatusSeeOther)
			return
		}

		if s.isAuthenticated(r) {
			http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
			return
		}
		s.renderTemplate(w, "login.gohtml", map[string]any{"Error": ""}, http.StatusOK)
	case http.MethodPost:
		if !s.hasConfiguredAdminCredentials() {
			http.Redirect(w, r, "/admin/setup", http.StatusSeeOther)
			return
		}

		if err := s.verifyOrigin(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		clientIP := extractClientIP(r.RemoteAddr)
		if s.isLocked(clientIP) {
			s.renderTemplate(w, "login.gohtml", map[string]any{"Error": "Too many failed attempts. Try again later."}, http.StatusTooManyRequests)
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		if !s.validateAdminCredentials(username, password) {
			s.recordFailedLogin(clientIP)
			s.renderTemplate(w, "login.gohtml", map[string]any{"Error": "Invalid admin credentials"}, http.StatusUnauthorized)
			return
		}
		s.clearFailedLogins(clientIP)

		if err := s.createSession(w); err != nil {
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := s.verifyCSRF(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}

	// #nosec G124 -- Secure is configurable for local HTTP admin use; HttpOnly and SameSite are enforced.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.config.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthenticated(r) {
		s.redirectToLogin(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		csrfToken, err := s.currentCSRFToken(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		s.renderUsers(w, usersViewData{CSRFToken: csrfToken}, http.StatusOK)
	case http.MethodPost:
		if err := s.verifyCSRF(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		rotatedCSRFToken, err := s.rotateCSRFToken(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		if err := validateUsername(username); err != nil {
			s.renderUsers(w, usersViewData{Error: err.Error(), CSRFToken: rotatedCSRFToken}, http.StatusBadRequest)
			return
		}

		if s.config.Credentials.Exists(username) {
			s.renderUsers(w, usersViewData{Error: "username already exists", CSRFToken: rotatedCSRFToken}, http.StatusConflict)
			return
		}

		password, err := generatePassword(20)
		if err != nil {
			s.renderUsers(w, usersViewData{Error: "failed to generate password", CSRFToken: rotatedCSRFToken}, http.StatusInternalServerError)
			return
		}

		s.config.Credentials.Add(username, password)
		if err := s.persistUsers(); err != nil {
			s.config.Credentials.Delete(username)
			s.renderUsers(w, usersViewData{Error: "failed to persist users", CSRFToken: rotatedCSRFToken}, http.StatusInternalServerError)
			return
		}

		s.renderUsers(w, usersViewData{
			Success:           "Proxy user created successfully.",
			GeneratedUsername: username,
			GeneratedPassword: password,
			CSRFToken:         rotatedCSRFToken,
		}, http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUserByName(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthenticated(r) {
		s.redirectToLogin(w, r)
		return
	}

	relativePath := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	cleanPath := path.Clean("/" + relativePath)
	segments := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	username := segments[0]
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost && len(segments) == 2 && segments[1] == "reset-password" {
		if err := s.verifyCSRF(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		rotatedCSRFToken, err := s.rotateCSRFToken(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		password, err := generatePassword(20)
		if err != nil {
			s.renderUsers(w, usersViewData{Error: "failed to generate password", CSRFToken: rotatedCSRFToken}, http.StatusInternalServerError)
			return
		}

		previousHash, existed := s.config.Credentials.GetHashed(username)
		if !existed {
			s.renderUsers(w, usersViewData{Error: "user not found", CSRFToken: rotatedCSRFToken}, http.StatusNotFound)
			return
		}

		s.config.Credentials.Add(username, password)
		if err := s.persistUsers(); err != nil {
			s.config.Credentials.SetHashed(username, previousHash)
			s.renderUsers(w, usersViewData{Error: "failed to persist users", CSRFToken: rotatedCSRFToken}, http.StatusInternalServerError)
			return
		}

		s.renderUsers(w, usersViewData{
			Success:           "Password reset successfully.",
			GeneratedUsername: username,
			GeneratedPassword: password,
			CSRFToken:         rotatedCSRFToken,
		}, http.StatusOK)
		return
	}

	if r.Method == http.MethodPost && len(segments) == 2 && segments[1] == "reset-stats" {
		if err := s.verifyCSRF(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		rotatedCSRFToken, err := s.rotateCSRFToken(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if !s.config.Credentials.Exists(username) {
			s.renderUsers(w, usersViewData{Error: "user not found", CSRFToken: rotatedCSRFToken}, http.StatusNotFound)
			return
		}

		s.config.Tracker.ResetUserStats(username)
		if err := s.persistTraffic(); err != nil {
			s.renderUsers(w, usersViewData{Error: "failed to reset stats", CSRFToken: rotatedCSRFToken}, http.StatusInternalServerError)
			return
		}

		s.renderUsers(w, usersViewData{
			Success:   "Traffic statistics reset successfully.",
			CSRFToken: rotatedCSRFToken,
		}, http.StatusOK)
		return
	}

	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := s.verifyCSRF(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rotatedCSRFToken, err := s.rotateCSRFToken(r)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	passwordHash, existed := s.config.Credentials.GetHashed(username)
	s.config.Credentials.Delete(username)
	if err := s.persistUsers(); err != nil {
		if existed {
			s.config.Credentials.SetHashed(username, passwordHash)
		}
		s.renderUsers(w, usersViewData{Error: "failed to persist users", CSRFToken: rotatedCSRFToken}, http.StatusInternalServerError)
		return
	}

	s.renderUsers(w, usersViewData{Success: "Proxy user deleted successfully.", CSRFToken: rotatedCSRFToken}, http.StatusOK)
}

func (s *Server) renderUsers(w http.ResponseWriter, data usersViewData, status int) {
	data.ProxyUsers = s.proxyUsersWithTraffic()
	data.TotalUsers = len(data.ProxyUsers)
	s.renderTemplate(w, "users.gohtml", data, status)
}

func (s *Server) handleUserRows(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthenticated(r) {
		s.redirectToLogin(w, r)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	rows := s.proxyUsersWithTraffic()
	s.renderTemplate(w, "user_rows.gohtml", usersViewData{ProxyUsers: rows, TotalUsers: len(rows)}, http.StatusOK)
}

func (s *Server) proxyUsersWithTraffic() []proxyUserView {
	usernames := s.config.Credentials.ListUsers()
	now := time.Now()
	rows := make([]proxyUserView, 0, len(usernames))
	byUser := make(map[string]*proxyUserView, len(usernames))
	startedByUser := make(map[string]time.Time, len(usernames))
	ipSetByUser := make(map[string]map[string]struct{}, len(usernames))
	totalByUser := make(map[string]traffic.UserTotals)

	for _, username := range usernames {
		row := proxyUserView{
			Username:      username,
			ActiveClients: 0,
			ClientIP:      "-",
			UploadRate:    "0 B/s",
			DownloadRate:  "0 B/s",
			UploadTotal:   "0 B",
			DownloadTotal: "0 B",
			Status:        statusOffline,
			StartedAgo:    "-",
		}
		rows = append(rows, row)
		byUser[username] = &rows[len(rows)-1]
		ipSetByUser[username] = make(map[string]struct{})
	}

	if s.config.Tracker == nil {
		return rows
	}
	totalByUser = s.config.Tracker.TotalsByUser()

	for _, item := range s.config.Tracker.Snapshot() {
		row, ok := byUser[item.Username]
		if !ok {
			continue
		}

		row.ActiveClients++
		row.Status = statusActive

		if item.ClientIP != "" {
			ipSetByUser[item.Username][item.ClientIP] = struct{}{}
		}

		if startedByUser[item.Username].IsZero() || item.StartedAt.Before(startedByUser[item.Username]) {
			startedByUser[item.Username] = item.StartedAt
		}
	}

	for i := range rows {
		totals := totalByUser[rows[i].Username]

		if rows[i].ActiveClients == 0 {
			if !totals.LastSeenAt.IsZero() {
				if now.Sub(totals.LastSeenAt) <= offlineInactivityWindow {
					rows[i].Status = statusActive
				}
				if totals.LastClientIP != "" {
					rows[i].ClientIP = totals.LastClientIP
				}
				rows[i].StartedAgo = formatStartedAgo(totals.LastSeenAt)
			}
			continue
		}

		ips := make([]string, 0, len(ipSetByUser[rows[i].Username]))
		for ip := range ipSetByUser[rows[i].Username] {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		rows[i].ClientIP = strings.Join(ips, ", ")
		rows[i].StartedAgo = formatStartedAgo(startedByUser[rows[i].Username])
	}

	for i := range rows {
		totals := totalByUser[rows[i].Username]
		rows[i].UploadRate = formatByteRate(totals.UploadBPS)
		rows[i].DownloadRate = formatByteRate(totals.DownloadBPS)
		rows[i].UploadTotal = formatBytes(totals.UploadBytes)
		rows[i].DownloadTotal = formatBytes(totals.DownloadBytes)
	}

	return rows
}

func formatByteRate(n uint64) string {
	return fmt.Sprintf("%s/s", formatBytes(n))
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for value := n / unit; value >= unit && exp < 5; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func formatStartedAgo(startedAt time.Time) string {
	if startedAt.IsZero() {
		return "unknown"
	}
	d := time.Since(startedAt)
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func (s *Server) renderTemplate(w http.ResponseWriter, name string, data any, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.config.Logger.Error().Err(err).Msg("failed to render template")
	}
}

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Header.Get("HX-Request"), "true") {
		w.Header().Set("HX-Redirect", "/admin/login")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (s *Server) persistUsers() error {
	if s.config.UserStore == nil {
		return nil
	}

	return s.config.UserStore.Save(s.config.Credentials.Snapshot())
}

func (s *Server) persistTraffic() error {
	if s.config.TrafficStore == nil || s.config.Tracker == nil {
		return nil
	}

	return s.config.TrafficStore.SaveTraffic(s.config.Tracker.TotalsByUser())
}

func (s *Server) validateAdminCredentials(username, password string) bool {
	storedUsername, storedPasswordHash, found := s.currentStoredAdminCredentials()
	if !found {
		return false
	}

	if subtle.ConstantTimeCompare([]byte(username), []byte(storedUsername)) != 1 {
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(password)) == nil
}

func (s *Server) createSession(w http.ResponseWriter) error {
	token, err := newRandomToken(32)
	if err != nil {
		return err
	}

	csrfToken, err := newRandomToken(32)
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(sessionTTL)
	s.mu.Lock()
	s.sessions[token] = session{ExpiresAt: expiresAt, CSRFToken: csrfToken}
	s.mu.Unlock()

	// #nosec G124 -- Secure is configurable for local HTTP admin use; HttpOnly and SameSite are enforced.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.config.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
	})

	return nil
}

func (s *Server) hasConfiguredAdminCredentials() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasConfiguredAdminCredentialsLocked()
}

func (s *Server) hasConfiguredAdminCredentialsLocked() bool {
	return s.admin.Username != "" && s.admin.PasswordHash != ""
}

func (s *Server) currentStoredAdminCredentials() (string, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.admin.Username == "" || s.admin.PasswordHash == "" {
		return "", "", false
	}

	return s.admin.Username, s.admin.PasswordHash, true
}

func (s *Server) bootstrapAdminCredentials(username, password string) error {
	if s.config.AdminStore == nil {
		return httpError("admin credential store is not configured")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.hasConfiguredAdminCredentialsLocked() {
		return httpError("admin credentials already configured")
	}

	if err := s.config.AdminStore.Save(username, string(passwordHash)); err != nil {
		return err
	}

	s.admin = adminCredential{Username: username, PasswordHash: string(passwordHash)}
	return nil
}

func (s *Server) isAuthenticated(r *http.Request) bool {
	_, ok := s.currentSession(r)
	return ok
}

func (s *Server) currentSession(r *http.Request) (session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return session{}, false
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[cookie.Value]
	if !ok {
		return session{}, false
	}
	if now.After(sess.ExpiresAt) {
		delete(s.sessions, cookie.Value)
		return session{}, false
	}

	return sess, true
}

func (s *Server) currentCSRFToken(r *http.Request) (string, error) {
	sess, ok := s.currentSession(r)
	if !ok {
		return "", httpError("invalid session")
	}

	return sess.CSRFToken, nil
}

func (s *Server) verifyCSRF(r *http.Request) error {
	if err := s.verifyOrigin(r); err != nil {
		return err
	}

	sess, ok := s.currentSession(r)
	if !ok {
		return httpError("invalid session")
	}

	provided := r.Header.Get("X-CSRF-Token")
	if provided == "" {
		if err := r.ParseForm(); err == nil {
			provided = r.FormValue("_csrf")
		}
	}

	if provided == "" {
		return httpError("csrf token required")
	}

	if subtle.ConstantTimeCompare([]byte(provided), []byte(sess.CSRFToken)) != 1 {
		return httpError("invalid csrf token")
	}

	return nil
}

func (s *Server) rotateCSRFToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", httpError("invalid session")
	}

	newToken, err := newRandomToken(32)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[cookie.Value]
	if !ok {
		return "", httpError("invalid session")
	}

	sess.CSRFToken = newToken
	s.sessions[cookie.Value] = sess

	return newToken, nil
}

func (s *Server) verifyOrigin(r *http.Request) error {
	if len(s.config.AllowedOrigins) == 0 {
		return nil
	}

	originHeader := strings.TrimSpace(r.Header.Get("Origin"))
	if originHeader != "" {
		origin, err := normalizeOrigin(originHeader)
		if err != nil {
			return httpError("invalid origin")
		}
		if s.isAllowedOrigin(origin) {
			return nil
		}
		return httpError("origin not allowed")
	}

	refererHeader := strings.TrimSpace(r.Header.Get("Referer"))
	if refererHeader != "" {
		refererURL, err := url.Parse(refererHeader)
		if err != nil || refererURL.Scheme == "" || refererURL.Host == "" {
			return httpError("invalid referer")
		}
		refererOrigin := refererURL.Scheme + "://" + refererURL.Host
		if s.isAllowedOrigin(strings.ToLower(refererOrigin)) {
			return nil
		}
		return httpError("referer not allowed")
	}

	return httpError("origin or referer required")
}

func (s *Server) isAllowedOrigin(origin string) bool {
	for _, allowed := range s.config.AllowedOrigins {
		if subtle.ConstantTimeCompare([]byte(origin), []byte(allowed)) == 1 {
			return true
		}
	}

	return false
}

func normalizeAllowedOrigins(origins []string) []string {
	if len(origins) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(origins))
	seen := make(map[string]struct{}, len(origins))
	for _, raw := range origins {
		origin, err := normalizeOrigin(raw)
		if err != nil {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		normalized = append(normalized, origin)
	}

	return normalized
}

func normalizeOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", httpError("invalid origin")
	}

	return strings.ToLower(parsed.Scheme + "://" + parsed.Host), nil
}

func (s *Server) isLocked(clientIP string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempt, ok := s.logins[clientIP]
	if !ok {
		return false
	}

	if attempt.LockedUntil.IsZero() {
		return false
	}

	if time.Now().After(attempt.LockedUntil) {
		delete(s.logins, clientIP)
		return false
	}

	return true
}

func (s *Server) recordFailedLogin(clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	attempt := s.logins[clientIP]

	if attempt.FirstFailed.IsZero() || now.Sub(attempt.FirstFailed) > s.config.LoginWindow {
		attempt.FirstFailed = now
		attempt.Count = 0
		attempt.LockedUntil = time.Time{}
	}

	attempt.Count++
	if attempt.Count >= s.config.MaxLoginAttempts {
		attempt.LockedUntil = now.Add(s.config.LockoutDuration)
	}

	s.logins[clientIP] = attempt
}

func (s *Server) clearFailedLogins(clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.logins, clientIP)
}

func extractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func newRandomToken(byteLength int) (string, error) {
	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func generatePassword(length int) (string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	if length <= 0 {
		return "", httpError("password length must be greater than zero")
	}

	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}

	var builder strings.Builder
	builder.Grow(length)
	for _, value := range bytes {
		builder.WriteByte(charset[int(value)%len(charset)])
	}

	return builder.String(), nil
}

func validateUsername(username string) error {
	if username == "" {
		return httpError("username is required")
	}
	if len(username) < minUsernameLength || len(username) > maxUsernameLength {
		return httpError("username must be between 3 and 64 characters")
	}
	if strings.Contains(username, ":") {
		return httpError("username cannot contain ':'")
	}
	if !usernamePattern.MatchString(username) {
		return httpError("username may only contain letters, numbers, dots, underscores, and hyphens")
	}
	return nil
}

type httpError string

func (e httpError) Error() string {
	return string(e)
}
