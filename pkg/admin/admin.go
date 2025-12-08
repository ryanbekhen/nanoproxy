package admin

import (
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"github.com/ryanbekhen/nanoproxy/pkg/userstore"
)

//go:embed templates/*.gohtml
var templatesFS embed.FS

// Config holds the configuration for the admin panel
type Config struct {
	UserStore   *userstore.Store
	Credentials credential.Store
	Logger      *zerolog.Logger
}

// Handler handles admin panel requests
type Handler struct {
	config    *Config
	templates *template.Template
}

// New creates a new admin handler
func New(config *Config) *Handler {
	// Parse templates
	tmpl, err := template.ParseFS(templatesFS, "templates/*.gohtml")
	if err != nil {
		config.Logger.Fatal().Err(err).Msg("Failed to parse templates")
	}

	return &Handler{
		config:    config,
		templates: tmpl,
	}
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authentication middleware
	if !h.authenticate(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Admin Panel"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Route requests
	switch {
	case r.URL.Path == "/admin" || r.URL.Path == "/admin/":
		h.handleAdminPanel(w, r)
	case r.URL.Path == "/admin/users-table":
		h.handleUsersTable(w, r)
	case r.URL.Path == "/admin/api/users" && r.Method == http.MethodGet:
		h.handleListUsers(w, r)
	case r.URL.Path == "/admin/api/users" && r.Method == http.MethodPost:
		h.handleCreateUser(w, r)
	case strings.HasPrefix(r.URL.Path, "/admin/api/users/") && r.Method == http.MethodPut:
		h.handleUpdateUser(w, r)
	case strings.HasPrefix(r.URL.Path, "/admin/api/users/") && r.Method == http.MethodDelete:
		h.handleDeleteUser(w, r)
	default:
		http.NotFound(w, r)
	}
}

// authenticate checks if the request has valid credentials
func (h *Handler) authenticate(r *http.Request) bool {
	if h.config.Credentials == nil {
		// No authentication required
		return true
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}

	return h.config.Credentials.Valid(username, password)
}

// handleAdminPanel serves the admin panel UI
func (h *Handler) handleAdminPanel(w http.ResponseWriter, r *http.Request) {
	users := h.config.UserStore.List()
	
	data := map[string]interface{}{
		"Users":     users,
		"UserCount": len(users),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "index.gohtml", data); err != nil {
		h.config.Logger.Error().Err(err).Msg("Failed to render template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleUsersTable renders just the users table partial
func (h *Handler) handleUsersTable(w http.ResponseWriter, r *http.Request) {
	users := h.config.UserStore.List()
	
	data := map[string]interface{}{
		"Users": users,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "users-table", data); err != nil {
		h.config.Logger.Error().Err(err).Msg("Failed to render users table")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleListUsers lists all users
func (h *Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users := h.config.UserStore.List()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": users,
		"count": len(users),
	})
}

// handleCreateUser creates a new user
func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var username, password string

	// Support both JSON and form data
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		username = req.Username
		password = req.Password
	} else {
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		username = r.FormValue("username")
		password = r.FormValue("password")
	}

	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	if err := h.config.UserStore.AddUser(username, password); err != nil {
		h.config.Logger.Error().Err(err).Msg("Failed to add user")
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	h.config.Logger.Info().Str("username", username).Msg("User created")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User created successfully",
	})
}

// handleUpdateUser updates a user's password
func (h *Handler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")

	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	// Check if user exists
	if _, exists := h.config.UserStore.Get(username); !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := h.config.UserStore.AddUser(username, req.Password); err != nil {
		h.config.Logger.Error().Err(err).Msg("Failed to update user")
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	h.config.Logger.Info().Str("username", username).Msg("User updated")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User updated successfully",
	})
}

// handleDeleteUser deletes a user
func (h *Handler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")

	// Check if user exists
	if _, exists := h.config.UserStore.Get(username); !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := h.config.UserStore.Delete(username); err != nil {
		h.config.Logger.Error().Err(err).Msg("Failed to delete user")
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	h.config.Logger.Info().Str("username", username).Msg("User deleted")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User deleted successfully",
	})
}
