package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"github.com/ryanbekhen/nanoproxy/pkg/userstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func setupTestHandler(t *testing.T) (*Handler, string) {
	tmpFile := "/tmp/test_admin_users.json"
	os.Remove(tmpFile) // Clean up any existing file

	store, err := userstore.NewStore(tmpFile)
	require.NoError(t, err)

	logger := zerolog.New(os.Stdout)

	// Create credentials for admin auth
	creds := credential.NewStaticCredentialStore()
	// Generate bcrypt hash for "admin" password
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	require.NoError(t, err)
	creds.Add("admin", string(hash))

	config := &Config{
		UserStore:   store,
		Credentials: creds,
		Logger:      &logger,
	}

	handler := New(config)
	return handler, tmpFile
}

func TestHandler_Authenticate(t *testing.T) {
	handler, tmpFile := setupTestHandler(t)
	defer os.Remove(tmpFile)

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
	}{
		{
			name:       "Valid credentials",
			username:   "admin",
			password:   "admin",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Invalid credentials",
			username:   "admin",
			password:   "wrong",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "No credentials",
			username:   "",
			password:   "",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/api/users", nil)
			if tt.username != "" {
				req.SetBasicAuth(tt.username, tt.password)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestHandler_ListUsers(t *testing.T) {
	handler, tmpFile := setupTestHandler(t)
	defer os.Remove(tmpFile)

	// Add test users
	handler.config.UserStore.AddUser("user1", "pass1")
	handler.config.UserStore.AddUser("user2", "pass2")

	req := httptest.NewRequest(http.MethodGet, "/admin/api/users", nil)
	req.SetBasicAuth("admin", "admin")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, float64(2), resp["count"])
	users := resp["users"].([]interface{})
	assert.Equal(t, 2, len(users))
}

func TestHandler_CreateUser(t *testing.T) {
	handler, tmpFile := setupTestHandler(t)
	defer os.Remove(tmpFile)

	tests := []struct {
		name       string
		payload    map[string]string
		wantStatus int
	}{
		{
			name: "Valid user",
			payload: map[string]string{
				"username": "testuser",
				"password": "testpass",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "Missing username",
			payload: map[string]string{
				"password": "testpass",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Missing password",
			payload: map[string]string{
				"username": "testuser",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/admin/api/users", bytes.NewReader(body))
			req.SetBasicAuth("admin", "admin")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestHandler_UpdateUser(t *testing.T) {
	handler, tmpFile := setupTestHandler(t)
	defer os.Remove(tmpFile)

	// Add a user first
	handler.config.UserStore.AddUser("testuser", "oldpass")

	tests := []struct {
		name       string
		username   string
		payload    map[string]string
		wantStatus int
	}{
		{
			name:     "Valid update",
			username: "testuser",
			payload: map[string]string{
				"password": "newpass",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:     "User not found",
			username: "nonexistent",
			payload: map[string]string{
				"password": "newpass",
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:     "Missing password",
			username: "testuser",
			payload:  map[string]string{},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest(http.MethodPut, "/admin/api/users/"+tt.username, bytes.NewReader(body))
			req.SetBasicAuth("admin", "admin")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestHandler_DeleteUser(t *testing.T) {
	handler, tmpFile := setupTestHandler(t)
	defer os.Remove(tmpFile)

	// Add a user first
	handler.config.UserStore.AddUser("testuser", "testpass")

	tests := []struct {
		name       string
		username   string
		wantStatus int
	}{
		{
			name:       "Valid delete",
			username:   "testuser",
			wantStatus: http.StatusOK,
		},
		{
			name:       "User not found",
			username:   "nonexistent",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/admin/api/users/"+tt.username, nil)
			req.SetBasicAuth("admin", "admin")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestHandler_AdminPanel(t *testing.T) {
	handler, tmpFile := setupTestHandler(t)
	defer os.Remove(tmpFile)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.SetBasicAuth("admin", "admin")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "NanoProxy User Management")
}
