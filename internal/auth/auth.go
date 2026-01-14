// Package auth provides OAuth authentication using AT Protocol.
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrStateNotFound   = errors.New("auth state not found")
)

// SQLiteAuthStore implements oauth.ClientAuthStore using SQLite for persistence.
type SQLiteAuthStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewSQLiteAuthStore creates a new SQLite-backed auth store.
func NewSQLiteAuthStore(db *sql.DB) (*SQLiteAuthStore, error) {
	store := &SQLiteAuthStore{db: db}
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("migrate auth tables: %w", err)
	}
	return store, nil
}

func (s *SQLiteAuthStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS oauth_sessions (
			did TEXT NOT NULL,
			session_id TEXT NOT NULL,
			data TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (did, session_id)
		);

		CREATE TABLE IF NOT EXISTS oauth_auth_requests (
			state TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_oauth_auth_requests_created_at ON oauth_auth_requests(created_at);
	`)
	return err
}

// GetSession implements oauth.ClientAuthStore
func (s *SQLiteAuthStore) GetSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var dataJSON string
	err := s.db.QueryRowContext(ctx, `
		SELECT data FROM oauth_sessions WHERE did = ? AND session_id = ?
	`, did.String(), sessionID).Scan(&dataJSON)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}

	var data oauth.ClientSessionData
	if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
		return nil, fmt.Errorf("unmarshal session data: %w", err)
	}

	return &data, nil
}

// SaveSession implements oauth.ClientAuthStore
func (s *SQLiteAuthStore) SaveSession(ctx context.Context, sess oauth.ClientSessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dataJSON, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal session data: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oauth_sessions (did, session_id, data, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(did, session_id) DO UPDATE SET
			data = excluded.data,
			updated_at = CURRENT_TIMESTAMP
	`, sess.AccountDID.String(), sess.SessionID, dataJSON)

	return err
}

// DeleteSession implements oauth.ClientAuthStore
func (s *SQLiteAuthStore) DeleteSession(ctx context.Context, did syntax.DID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_sessions WHERE did = ? AND session_id = ?`, did.String(), sessionID)
	return err
}

// GetAuthRequestInfo implements oauth.ClientAuthStore
func (s *SQLiteAuthStore) GetAuthRequestInfo(ctx context.Context, state string) (*oauth.AuthRequestData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var dataJSON string
	err := s.db.QueryRowContext(ctx, `
		SELECT data FROM oauth_auth_requests WHERE state = ?
	`, state).Scan(&dataJSON)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query auth request: %w", err)
	}

	var data oauth.AuthRequestData
	if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
		return nil, fmt.Errorf("unmarshal auth request data: %w", err)
	}

	return &data, nil
}

// SaveAuthRequestInfo implements oauth.ClientAuthStore
func (s *SQLiteAuthStore) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dataJSON, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal auth request data: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oauth_auth_requests (state, data)
		VALUES (?, ?)
	`, info.State, dataJSON)

	return err
}

// DeleteAuthRequestInfo implements oauth.ClientAuthStore
func (s *SQLiteAuthStore) DeleteAuthRequestInfo(ctx context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_auth_requests WHERE state = ?`, state)
	return err
}

// CleanupExpiredRequests removes auth requests older than 10 minutes.
func (s *SQLiteAuthStore) CleanupExpiredRequests(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
		DELETE FROM oauth_auth_requests WHERE created_at < datetime('now', '-10 minutes')
	`)
	return err
}

// Session represents an authenticated user session for the web app.
// This is separate from the OAuth session data and is used for browser cookies.
type Session struct {
	DID       syntax.DID
	Handle    string
	SessionID string // The OAuth session ID from indigo
}

// UserSessionStore manages browser sessions (cookies), mapping to OAuth sessions.
type UserSessionStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewUserSessionStore creates a new user session store.
func NewUserSessionStore(db *sql.DB) (*UserSessionStore, error) {
	store := &UserSessionStore{db: db}
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("migrate user session tables: %w", err)
	}
	return store, nil
}

func (s *UserSessionStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS user_sessions (
			cookie_id TEXT PRIMARY KEY,
			did TEXT NOT NULL,
			handle TEXT NOT NULL,
			oauth_session_id TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_user_sessions_did ON user_sessions(did);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
	`)
	return err
}

// CreateSession creates a new user session.
func (s *UserSessionStore) CreateSession(ctx context.Context, cookieID string, did syntax.DID, handle, oauthSessionID string, duration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiresAt := time.Now().Add(duration)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_sessions (cookie_id, did, handle, oauth_session_id, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, cookieID, did.String(), handle, oauthSessionID, expiresAt)

	return err
}

// GetSession retrieves a user session by cookie ID.
func (s *UserSessionStore) GetSession(ctx context.Context, cookieID string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var didStr, handle, oauthSessionID string

	err := s.db.QueryRowContext(ctx, `
		SELECT did, handle, oauth_session_id FROM user_sessions
		WHERE cookie_id = ? AND expires_at > CURRENT_TIMESTAMP
	`, cookieID).Scan(&didStr, &handle, &oauthSessionID)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}

	did, err := syntax.ParseDID(didStr)
	if err != nil {
		return nil, fmt.Errorf("parse DID: %w", err)
	}

	return &Session{
		DID:       did,
		Handle:    handle,
		SessionID: oauthSessionID,
	}, nil
}

// DeleteSession removes a user session.
func (s *UserSessionStore) DeleteSession(ctx context.Context, cookieID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `DELETE FROM user_sessions WHERE cookie_id = ?`, cookieID)
	return err
}

// CleanupExpiredSessions removes expired sessions.
func (s *UserSessionStore) CleanupExpiredSessions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP`)
	return err
}

// OAuthService wraps indigo's OAuth ClientApp for easier use.
type OAuthService struct {
	app       *oauth.ClientApp
	authStore *SQLiteAuthStore
}

// NewOAuthService creates a new OAuth service.
func NewOAuthService(clientID, callbackURL string, scopes []string, authStore *SQLiteAuthStore) *OAuthService {
	var config oauth.ClientConfig
	if strings.HasPrefix(clientID, "http://localhost") || strings.HasPrefix(clientID, "http://127.0.0.1") {
		config = oauth.NewLocalhostConfig(callbackURL, scopes)
	} else {
		config = oauth.NewPublicConfig(clientID, callbackURL, scopes)
	}
	config.UserAgent = "solanum/1.0"

	app := oauth.NewClientApp(&config, authStore)

	return &OAuthService{
		app:       app,
		authStore: authStore,
	}
}

// StartAuthFlow initiates the OAuth flow for a handle or DID.
// Returns the authorization URL to redirect the user to.
func (s *OAuthService) StartAuthFlow(ctx context.Context, identifier string) (string, error) {
	// Clean up identifier (remove @ prefix if present)
	identifier = strings.TrimPrefix(identifier, "@")

	return s.app.StartAuthFlow(ctx, identifier)
}

// ProcessCallback handles the OAuth callback and returns session data.
func (s *OAuthService) ProcessCallback(ctx context.Context, state, code, iss string) (*oauth.ClientSessionData, error) {
	// Build the callback params as the library expects
	params := make(map[string][]string)
	params["state"] = []string{state}
	params["code"] = []string{code}
	params["iss"] = []string{iss}

	return s.app.ProcessCallback(ctx, params)
}

// ResumeSession retrieves an existing OAuth session.
func (s *OAuthService) ResumeSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSession, error) {
	return s.app.ResumeSession(ctx, did, sessionID)
}

// Logout logs out the user by revoking tokens and deleting session.
func (s *OAuthService) Logout(ctx context.Context, did syntax.DID, sessionID string) error {
	return s.app.Logout(ctx, did, sessionID)
}
