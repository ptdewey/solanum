// Package handlers provides HTTP handlers for the web application.
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/patricktcoakley/solanum/internal/auth"
	"github.com/patricktcoakley/solanum/internal/feed"
	"github.com/patricktcoakley/solanum/internal/pds"
	"github.com/rs/zerolog"
)

const sessionCookieName = "solanum_session"

const descLimit = 150

// App holds application dependencies for handlers.
type App struct {
	OAuth        *auth.OAuthService
	AuthStore    *auth.SQLiteAuthStore
	UserSessions *auth.UserSessionStore
	FeedService  *feed.Service
	Templates    map[string]*template.Template
	Logger       zerolog.Logger
	IsProduction bool
}

// AuthHandler handles OAuth authentication flow.
type AuthHandler struct {
	app *App
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(app *App) *AuthHandler {
	return &AuthHandler{app: app}
}

// ClientMetadata serves the OAuth client metadata document.
func (h *AuthHandler) ClientMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := h.app.OAuth.ClientMetadata()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		h.app.Logger.Error().Err(err).Msg("encode client metadata")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// LoginPage renders the login form.
func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	session := getSession(r.Context())
	if session != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	tmpl, ok := h.app.Templates["login.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("login template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "base", nil); err != nil {
		h.app.Logger.Error().Err(err).Msg("render login page")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// StartAuth initiates the OAuth flow.
func (h *AuthHandler) StartAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	handle := strings.TrimSpace(r.FormValue("handle"))
	if handle == "" {
		http.Error(w, "Handle is required", http.StatusBadRequest)
		return
	}

	authURL, err := h.app.OAuth.StartAuthFlow(r.Context(), handle)
	if err != nil {
		h.app.Logger.Error().Err(err).Str("handle", handle).Msg("start auth failed")
		http.Error(w, "Failed to start authentication", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback handles the OAuth callback.
func (h *AuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	iss := r.URL.Query().Get("iss")

	// Check for error response from auth server
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		errDesc := r.URL.Query().Get("error_description")
		h.app.Logger.Error().Str("error", errCode).Str("description", errDesc).Msg("auth callback error")
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	if state == "" || code == "" || iss == "" {
		h.app.Logger.Error().
			Bool("has_state", state != "").
			Bool("has_code", code != "").
			Bool("has_iss", iss != "").
			Msg("Missing required OAuth parameters")
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	sessData, err := h.app.OAuth.ProcessCallback(r.Context(), state, code, iss)
	if err != nil {
		h.app.Logger.Error().Err(err).Str("iss", iss).Msg("complete auth failed")
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Session fixation protection: delete any existing session before creating new one
	if existingCookie, err := r.Cookie(sessionCookieName); err == nil {
		h.app.UserSessions.DeleteSession(r.Context(), existingCookie.Value)
	}

	// Create browser session cookie
	cookieID, err := generateSessionID()
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("generate session ID failed")
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Get handle from the session (we need to look it up)
	sess, err := h.app.OAuth.ResumeSession(r.Context(), sessData.AccountDID, sessData.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("failed to resume session after callback")
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Resolve DID to get handle via AT Protocol identity resolution
	handle := sessData.AccountDID.String() // Fallback to DID
	avatar := ""

	// Use default directory to resolve DID to handle
	dir := identity.DefaultDirectory()
	ident, err := dir.LookupDID(r.Context(), sessData.AccountDID)
	if err != nil {
		h.app.Logger.Warn().Err(err).Msg("failed to resolve DID to handle, using DID as fallback")
	} else if ident != nil && ident.Handle.String() != "" && ident.Handle.String() != "handle.invalid" {
		handle = ident.Handle.String()
	}

	// Fetch user profile from their PDS to get avatar
	apiClient := sess.APIClient()
	pdsClient := pds.NewClient(apiClient, sessData.AccountDID)
	profile, err := pdsClient.GetProfile(r.Context())
	if err != nil {
		h.app.Logger.Warn().Err(err).Msg("failed to fetch user profile from PDS, proceeding without avatar")
	} else if profile != nil {
		avatar = profile.Avatar
	}

	if err := h.app.UserSessions.CreateSession(r.Context(), cookieID, sessData.AccountDID, handle, avatar, sessData.SessionID, 7*24*time.Hour); err != nil {
		h.app.Logger.Error().Err(err).Msg("create user session failed")
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	// Note: SameSite=Lax works for OAuth callback redirects (which are GET requests)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.app.IsProduction, // Always secure in production, even behind reverse proxy
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})

	h.app.Logger.Info().
		Str("did", sessData.AccountDID.String()).
		Msg("User logged in successfully")

	http.Redirect(w, r, "/", http.StatusFound)
}

// Logout logs the user out.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		// Get the user session to find the OAuth session ID
		userSess, err := h.app.UserSessions.GetSession(r.Context(), cookie.Value)
		if err == nil {
			// Logout from OAuth (revoke tokens)
			if err := h.app.OAuth.Logout(r.Context(), userSess.DID, userSess.SessionID); err != nil {
				h.app.Logger.Warn().Err(err).Msg("failed to logout from OAuth")
			}
		}
		h.app.UserSessions.DeleteSession(r.Context(), cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}

// FeedHandler handles feed-related requests.
type FeedHandler struct {
	app *App
}

// NewFeedHandler creates a new feed handler.
func NewFeedHandler(app *App) *FeedHandler {
	return &FeedHandler{app: app}
}

// ListFeeds shows all user's feeds.
func (h *FeedHandler) ListFeeds(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	feeds, err := pdsClient.ListFeeds(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("list feeds")
		http.Error(w, "Failed to load feeds", http.StatusInternalServerError)
		return
	}

	// Truncate descriptions for display
	for i := range feeds {
		if len(feeds[i].Description) > descLimit {
			feeds[i].Description = feeds[i].Description[:descLimit] + "..."
		}
	}

	data := map[string]interface{}{
		"Session": session,
		"Feeds":   feeds,
	}

	tmpl, ok := h.app.Templates["feeds.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("feeds template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.app.Logger.Error().Err(err).Msg("render feeds page")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// AddFeed handles adding a new feed.
func (h *FeedHandler) AddFeed(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	feedURL := strings.TrimSpace(r.FormValue("url"))
	if feedURL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Fetch feed metadata
	metadata, err := h.app.FeedService.FetchMetadata(r.Context(), feedURL)
	if err != nil {
		h.app.Logger.Error().Err(err).Str("url", feedURL).Msg("fetch feed metadata")
		http.Error(w, "Failed to fetch feed", http.StatusBadRequest)
		return
	}

	// Get OAuth session and create feed in PDS
	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	newFeed := &pds.Feed{
		URL:         feedURL,
		Title:       metadata.Title,
		Description: metadata.Description,
		IsActive:    true,
	}

	_, _, err = pdsClient.CreateFeed(r.Context(), newFeed)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("create feed in PDS")
		http.Error(w, "Failed to save feed", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/feeds", http.StatusFound)
}

// DeleteFeed removes a feed.
func (h *FeedHandler) DeleteFeed(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rkey := r.PathValue("rkey")
	if rkey == "" {
		http.Error(w, "Feed ID required", http.StatusBadRequest)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	if err := pdsClient.DeleteFeed(r.Context(), rkey); err != nil {
		h.app.Logger.Error().Err(err).Str("rkey", rkey).Msg("delete feed")
		http.Error(w, "Failed to delete feed", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/feeds", http.StatusFound)
}

// ImportPage shows the import feeds page.
func (h *FeedHandler) ImportPage(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	data := map[string]interface{}{
		"Session": session,
	}

	tmpl, ok := h.app.Templates["import.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("import template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.app.Logger.Error().Err(err).Msg("render import page")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// LeafletFeedResult represents a resolved Leaflet subscription for the import UI.
type LeafletFeedResult struct {
	Publication string // AT URI
	Title       string
	RSSURL      string
	Error       string
}

// LeafletSubscriptionView represents a Leaflet subscription for display without fetching feed details.
type LeafletSubscriptionView struct {
	Publication string // AT URI
	Title       string
	RSSURL      string // RSS URL for display
}

// FetchLeafletFeeds fetches Leaflet subscriptions and displays them for selection.
// RSS URLs are resolved for display, but feed content is only fetched when importing.
func (h *FeedHandler) FetchLeafletFeeds(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<div class="import-result error">Authentication error. Please try logging in again.</div>`))
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)

	// Get Leaflet subscriptions
	leafletSubs, err := pdsClient.ListLeafletSubscriptions(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("list leaflet subscriptions")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<div class="import-result error">Failed to load Leaflet subscriptions.</div>`))
		return
	}

	if len(leafletSubs) == 0 {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<div class="empty">No Leaflet subscriptions found in your account.</div>`))
		return
	}

	// Get existing feeds to filter out already imported ones
	existingFeeds, err := pdsClient.ListFeeds(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("list feeds")
		existingFeeds = []pds.Feed{} // Non-fatal, continue
	}

	existingURLs := make(map[string]bool)
	for _, feed := range existingFeeds {
		existingURLs[feed.URL] = true
	}

	// Resolve RSS URLs and fetch titles for display
	var available []LeafletSubscriptionView
	var alreadyImported int

	for _, sub := range leafletSubs {
		// Resolve the RSS URL for display purposes
		rssURL, err := pdsClient.GetLeafletFeedRSSURL(r.Context(), sub.Publication)
		if err != nil {
			h.app.Logger.Warn().Err(err).Str("publication", sub.Publication).Msg("failed to resolve RSS URL, skipping")
			continue
		}

		// Skip if already imported
		if existingURLs[rssURL] {
			alreadyImported++
			continue
		}

		// Use title from subscription if available
		title := sub.Title

		// If no title, fetch it from the RSS feed
		if title == "" {
			metadata, err := h.app.FeedService.FetchMetadata(r.Context(), rssURL)
			if err != nil {
				h.app.Logger.Warn().Err(err).Str("url", rssURL).Msg("failed to fetch feed title, using URL")
				title = rssURL
			} else if metadata.Title != "" {
				title = metadata.Title
			} else {
				title = rssURL
			}
		}

		available = append(available, LeafletSubscriptionView{
			Publication: sub.Publication,
			Title:       title,
			RSSURL:      rssURL,
		})
	}

	// Render the results as HTML partial
	w.Header().Set("Content-Type", "text/html")
	h.renderLeafletSubscriptions(w, available, alreadyImported)
}

func (h *FeedHandler) renderLeafletSubscriptions(w http.ResponseWriter, subscriptions []LeafletSubscriptionView, alreadyImported int) {
	tmpl, ok := h.app.Templates["import.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("import template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Subscriptions   []LeafletSubscriptionView
		AlreadyImported int
	}{
		Subscriptions:   subscriptions,
		AlreadyImported: alreadyImported,
	}

	if err := tmpl.ExecuteTemplate(w, "leaflet-subscriptions", data); err != nil {
		h.app.Logger.Error().Err(err).Msg("render leaflet subscriptions")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (h *FeedHandler) renderLeafletResults(w http.ResponseWriter, available, failed []LeafletFeedResult, alreadyImported int) {
	tmpl, ok := h.app.Templates["import.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("import template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Available       []LeafletFeedResult
		Failed          []LeafletFeedResult
		AlreadyImported int
	}{
		Available:       available,
		Failed:          failed,
		AlreadyImported: alreadyImported,
	}

	if err := tmpl.ExecuteTemplate(w, "leaflet-results", data); err != nil {
		h.app.Logger.Error().Err(err).Msg("render leaflet results")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// ImportSelectedLeafletFeeds imports the selected Leaflet feeds.
// RSS URLs are resolved here when the user submits the import form.
func (h *FeedHandler) ImportSelectedLeafletFeeds(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Get the selected publication URIs from the form
	publicationURIs := r.Form["publication"]
	if len(publicationURIs) == 0 {
		http.Error(w, "No feeds selected", http.StatusBadRequest)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)

	imported := 0
	for _, publicationURI := range publicationURIs {
		// Resolve the RSS URL from the publication URI
		rssURL, err := pdsClient.GetLeafletFeedRSSURL(r.Context(), publicationURI)
		if err != nil {
			h.app.Logger.Error().Err(err).Str("publication", publicationURI).Msg("resolve leaflet RSS URL")
			continue
		}

		// Fetch feed metadata
		metadata, err := h.app.FeedService.FetchMetadata(r.Context(), rssURL)
		if err != nil {
			h.app.Logger.Error().Err(err).Str("url", rssURL).Msg("fetch feed metadata")
			continue
		}

		// Create feed in PDS
		newFeed := &pds.Feed{
			URL:         rssURL,
			Title:       metadata.Title,
			Description: metadata.Description,
			IsActive:    true,
		}

		_, _, err = pdsClient.CreateFeed(r.Context(), newFeed)
		if err != nil {
			h.app.Logger.Error().Err(err).Str("url", rssURL).Msg("create feed in PDS")
			continue
		}

		imported++
	}

	h.app.Logger.Info().Int("imported", imported).Int("selected", len(publicationURIs)).Msg("leaflet import complete")
	http.Redirect(w, r, "/feeds", http.StatusFound)
}

// RemoveEntry marks an entry as removed by adding it to the removed entries blob.
func (h *FeedHandler) RemoveEntry(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	entryURL := strings.TrimSpace(r.FormValue("url"))
	if entryURL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)

	// Add URL to removed entries
	if err := pdsClient.AddRemovedEntry(r.Context(), entryURL); err != nil {
		h.app.Logger.Error().Err(err).Str("url", entryURL).Msg("add removed entry")
		http.Error(w, "Failed to remove entry", http.StatusInternalServerError)
		return
	}

	// Return success response for HTMX
	w.WriteHeader(http.StatusOK)
}

// MarkEntryAsRead marks an entry as read by adding it to the archive blob.
func (h *FeedHandler) MarkEntryAsRead(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	entryURL := strings.TrimSpace(r.FormValue("url"))
	title := strings.TrimSpace(r.FormValue("title"))
	description := strings.TrimSpace(r.FormValue("description"))

	if entryURL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// If title is empty, fetch it from the page
	if title == "" {
		htmlMeta, err := h.app.FeedService.FetchHTMLMetadata(r.Context(), entryURL)
		if err != nil {
			h.app.Logger.Warn().Err(err).Str("url", entryURL).Msg("failed to fetch HTML metadata, using URL as title")
			title = entryURL
		} else {
			title = htmlMeta.Title
			if description == "" {
				description = htmlMeta.Description
			}
		}
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)

	// Add to archive blob
	archiveItem := pds.ReadingArchiveItem{
		URL:         entryURL,
		Title:       title,
		Description: truncateDescription(description, 120),
		ArchivedAt:  time.Now().UTC(),
	}

	if err := pdsClient.AddArchivedItem(r.Context(), archiveItem); err != nil {
		h.app.Logger.Error().Err(err).Msg("add to archive blob")
		http.Error(w, "Failed to mark as read", http.StatusInternalServerError)
		return
	}

	// Also add to removed entries
	if err := pdsClient.AddRemovedEntry(r.Context(), entryURL); err != nil {
		h.app.Logger.Warn().Err(err).Str("url", entryURL).Msg("failed to add to removed entries, but item was archived")
	}

	// Return success response for HTMX
	w.WriteHeader(http.StatusOK)
}

// truncateDescription truncates a description to the specified max length.
func truncateDescription(desc string, maxLen int) string {
	if len(desc) <= maxLen {
		return desc
	}
	return desc[:maxLen-3] + "..."
}

// RefreshFeeds fetches all RSS feeds and updates the PDS blob cache.
func (h *FeedHandler) RefreshFeeds(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)

	// Get all active feeds
	feeds, err := pdsClient.ListFeeds(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("list feeds")
		http.Error(w, "Failed to load feeds", http.StatusInternalServerError)
		return
	}

	// Fetch items from all feeds
	var allItems []pds.FeedCacheItem
	for _, feed := range feeds {
		if !feed.IsActive {
			continue
		}

		// Fetch feed items for the PDS blob cache
		metadata, items, err := h.app.FeedService.FetchFeed(r.Context(), feed.URL)
		if err != nil {
			h.app.Logger.Error().Err(err).Str("url", feed.URL).Msg("fetch feed")
			continue
		}

		// Use feed title from metadata if available, otherwise use stored title
		feedTitle := feed.Title
		if metadata.Title != "" {
			feedTitle = metadata.Title
		}

		// Convert to cache items
		for _, item := range items {
			description := item.Description
			if len(description) > descLimit {
				description = description[:descLimit] + "..."
			}

			cacheItem := pds.FeedCacheItem{
				ID:          item.ID,
				FeedURL:     feed.URL,
				FeedTitle:   feedTitle,
				Title:       item.Title,
				Description: description,
				Link:        item.Link,
				Author:      item.Author,
				Published:   item.Published,
				// Content field intentionally omitted - we only need metadata in cache
			}
			allItems = append(allItems, cacheItem)
		}
	}

	// Get removed URLs to filter them out before saving to cache
	removedURLs, err := pdsClient.GetRemovedURLs(r.Context())
	if err != nil {
		h.app.Logger.Warn().Err(err).Msg("failed to get removed URLs, proceeding without filtering")
		removedURLs = []string{}
	}

	// Create a set of removed URLs for fast lookup
	removedSet := make(map[string]bool)
	for _, url := range removedURLs {
		removedSet[url] = true
	}

	// Filter out removed entries BEFORE sorting and limiting
	var filteredItems []pds.FeedCacheItem
	for _, item := range allItems {
		if !removedSet[item.Link] {
			filteredItems = append(filteredItems, item)
		}
	}

	// Sort filtered items by published date (most recent first)
	sort.Slice(filteredItems, func(i, j int) bool {
		return filteredItems[i].Published.After(filteredItems[j].Published)
	})

	// Limit to most recent 200 items total
	if len(filteredItems) > 200 {
		filteredItems = filteredItems[:200]
	}

	// Create cache data JSON
	cacheData := pds.FeedCacheData{
		LastUpdated: time.Now().UTC(),
		Items:       filteredItems,
	}

	jsonData, err := json.Marshal(cacheData)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("marshal cache data")
		http.Error(w, "Failed to create cache", http.StatusInternalServerError)
		return
	}

	// Upload blob to PDS
	// HACK: once pds json blob mimetype issue is fixed, swap to 'application/json'
	blobRef, err := pdsClient.UploadBlob(r.Context(), jsonData, "text/plain")
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("upload blob")
		http.Error(w, "Failed to upload cache", http.StatusInternalServerError)
		return
	}

	// Create/update cache record
	cache := &pds.FeedCache{
		Blob:        *blobRef,
		LastUpdated: time.Now().UTC(),
		ItemCount:   len(filteredItems),
		FeedCount:   len(feeds),
	}

	_, err = pdsClient.CreateFeedCache(r.Context(), cache)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("create feed cache")
		http.Error(w, "Failed to save cache", http.StatusInternalServerError)
		return
	}

	h.app.Logger.Info().
		Int("items", len(filteredItems)).
		Int("feeds", len(feeds)).
		Msg("Feed cache refreshed successfully")

	// Return JSON response in same format as GetFeedCache
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"exists":      true,
		"lastUpdated": cacheData.LastUpdated,
		"items":       cacheData.Items,
	})
}

// GetFeedCache retrieves the cached feed items from the PDS blob.
func (h *FeedHandler) GetFeedCache(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)

	// Get cache record
	cache, err := pdsClient.GetFeedCache(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("get feed cache")
		// Return empty cache if not found
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"exists": false,
			"items":  []pds.FeedCacheItem{},
		})
		return
	}

	// Download blob
	blobData, mimeType, err := pdsClient.GetBlob(r.Context(), cache.Blob.Ref.Link)
	if err != nil {
		h.app.Logger.Error().
			Err(err).
			Str("cid", cache.Blob.Ref.Link).
			Str("did", session.DID.String()).
			Msg("get blob failed - this is likely a PDS bug, see error for details")
		http.Error(w, "Failed to load cache due to PDS blob serving issue", http.StatusInternalServerError)
		return
	}

	// Parse cache data (ignore mime type since PDS may not set it correctly)
	var cacheData pds.FeedCacheData
	if err := json.Unmarshal(blobData, &cacheData); err != nil {
		h.app.Logger.Error().
			Err(err).
			Int("dataSize", len(blobData)).
			Str("mimeType", mimeType).
			Str("dataPreview", string(blobData[:min(200, len(blobData))])).
			Msg("unmarshal cache data failed")
		http.Error(w, "Invalid cache data", http.StatusInternalServerError)
		return
	}

	// Filter out removed entries
	removedURLs, err := pdsClient.GetRemovedURLs(r.Context())
	if err != nil {
		h.app.Logger.Warn().Err(err).Msg("failed to get removed URLs, proceeding without filtering")
		removedURLs = []string{}
	}

	// Create a set of removed URLs for fast lookup
	removedSet := make(map[string]bool)
	for _, url := range removedURLs {
		removedSet[url] = true
	}

	// Filter items
	filteredItems := make([]pds.FeedCacheItem, 0, len(cacheData.Items))
	for _, item := range cacheData.Items {
		if !removedSet[item.Link] {
			filteredItems = append(filteredItems, item)
		}
	}

	// Return cache data
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"exists":      true,
		"lastUpdated": cacheData.LastUpdated,
		"items":       filteredItems,
	})
}

// DebugFeedCache returns debug information about the feed cache.
func (h *FeedHandler) DebugFeedCache(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)

	// Get cache record
	cache, err := pdsClient.GetFeedCache(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  "Cache not found",
			"exists": false,
		})
		return
	}

	// Download blob
	blobData, mimeType, err := pdsClient.GetBlob(r.Context(), cache.Blob.Ref.Link)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":    "Failed to retrieve blob",
			"exists":   true,
			"record":   cache,
			"blobSize": 0,
		})
		return
	}

	// Parse cache data
	var cacheData pds.FeedCacheData
	parseErr := json.Unmarshal(blobData, &cacheData)

	// Return debug info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"exists":       true,
		"record":       cache,
		"blobCID":      cache.Blob.Ref.Link,
		"blobSize":     len(blobData),
		"blobMimeType": mimeType,
		"recordSize":   cache.Blob.Size,
		"itemCount":    len(cacheData.Items),
		"parseError":   parseErr,
		"lastUpdated":  cacheData.LastUpdated,
	})
}

// ReadingListHandler handles reading list requests.
type ReadingListHandler struct {
	app *App
}

// NewReadingListHandler creates a new reading list handler.
func NewReadingListHandler(app *App) *ReadingListHandler {
	return &ReadingListHandler{app: app}
}

// ListItems shows the reading list.
func (h *ReadingListHandler) ListItems(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	items, err := pdsClient.ListReadingItems(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("list reading items")
		http.Error(w, "Failed to load reading list", http.StatusInternalServerError)
		return
	}

	// Check if there are any archived items
	archivedItems, err := pdsClient.GetArchivedItems(r.Context())
	hasArchived := err == nil && len(archivedItems) > 0

	data := map[string]interface{}{
		"Session":     session,
		"Active":      items,
		"HasArchived": hasArchived,
	}

	tmpl, ok := h.app.Templates["reading_list.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("reading_list template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.app.Logger.Error().Err(err).Msg("render reading list page")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// ArchivePage shows archived reading list items from the archive blob.
func (h *ReadingListHandler) ArchivePage(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	archivedItems, err := pdsClient.GetArchivedItems(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("get archived items")
		http.Error(w, "Failed to load archive", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Session":  session,
		"Archived": archivedItems,
	}

	tmpl, ok := h.app.Templates["archive.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("archive template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.app.Logger.Error().Err(err).Msg("render archive page")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// AddItem adds an item to the reading list.
func (h *ReadingListHandler) AddItem(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	itemURL := strings.TrimSpace(r.FormValue("url"))
	title := strings.TrimSpace(r.FormValue("title"))
	description := strings.TrimSpace(r.FormValue("description"))

	if itemURL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// If title is empty, fetch it from the page
	if title == "" {
		htmlMeta, err := h.app.FeedService.FetchHTMLMetadata(r.Context(), itemURL)
		if err != nil {
			h.app.Logger.Warn().Err(err).Str("url", itemURL).Msg("failed to fetch HTML metadata, using URL as title")
			title = itemURL
		} else {
			title = htmlMeta.Title
			// Also use description from page if not provided
			if description == "" {
				description = htmlMeta.Description
			}
		}
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	item := &pds.ReadingItem{
		URL:         itemURL,
		Title:       title,
		Description: description,
	}

	_, _, err = pdsClient.CreateReadingItem(r.Context(), item)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("create reading item")
		http.Error(w, "Failed to save item", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/reading-list", http.StatusFound)
}

// ArchiveItem marks an item as archived.
func (h *ReadingListHandler) ArchiveItem(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rkey := r.PathValue("rkey")
	if rkey == "" {
		http.Error(w, "Item ID required", http.StatusBadRequest)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	if err := pdsClient.ArchiveReadingItem(r.Context(), rkey); err != nil {
		h.app.Logger.Error().Err(err).Str("rkey", rkey).Msg("archive reading item")
		http.Error(w, "Failed to archive item", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/reading-list", http.StatusFound)
}

// DeleteItem removes an item from the reading list.
func (h *ReadingListHandler) DeleteItem(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rkey := r.PathValue("rkey")
	if rkey == "" {
		http.Error(w, "Item ID required", http.StatusBadRequest)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	if err := pdsClient.DeleteReadingItem(r.Context(), rkey); err != nil {
		h.app.Logger.Error().Err(err).Str("rkey", rkey).Msg("delete reading item")
		http.Error(w, "Failed to delete item", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/reading-list", http.StatusFound)
}

// DeleteArchivedItem removes an item from the archive blob by URL.
func (h *ReadingListHandler) DeleteArchivedItem(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	itemURL := strings.TrimSpace(r.FormValue("url"))
	if itemURL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	if err := pdsClient.RemoveArchivedItem(r.Context(), itemURL); err != nil {
		h.app.Logger.Error().Err(err).Str("url", itemURL).Msg("delete archived item")
		http.Error(w, "Failed to delete item", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/reading-list/archive", http.StatusFound)
}

// HomeHandler shows the home page with recent feed items.
type HomeHandler struct {
	app *App
}

// NewHomeHandler creates a new home handler.
func NewHomeHandler(app *App) *HomeHandler {
	return &HomeHandler{app: app}
}

const itemsPerPage = 25

// FeedItemView is a view model for displaying feed items with their feed title.
type FeedItemView struct {
	FeedTitle   string
	Title       string
	Description string
	Link        string
	Author      string
	Published   time.Time
}

// Home shows the home page.
func (h *HomeHandler) Home(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())

	if session == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Get user's feeds
	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	feeds, err := pdsClient.ListFeeds(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("list feeds")
		http.Error(w, "Failed to load feeds", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Session": session,
		"Feeds":   feeds,
	}

	tmpl, ok := h.app.Templates["home.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("home template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.app.Logger.Error().Err(err).Msg("render home page")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// FeedView shows items from a single feed.
func (h *HomeHandler) FeedView(w http.ResponseWriter, r *http.Request) {
	session := getSession(r.Context())
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	feedRKey := r.PathValue("rkey")
	if feedRKey == "" {
		http.Error(w, "Feed not found", http.StatusNotFound)
		return
	}

	// Get user's feeds
	oauthSess, err := h.app.OAuth.ResumeSession(r.Context(), session.DID, session.SessionID)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("resume oauth session")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}

	apiClient := oauthSess.APIClient()
	pdsClient := pds.NewClient(apiClient, session.DID)
	feeds, err := pdsClient.ListFeeds(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("list feeds")
		http.Error(w, "Failed to load feeds", http.StatusInternalServerError)
		return
	}

	// Find the specific feed
	var currentFeed *pds.Feed
	for i := range feeds {
		if feeds[i].RKey == feedRKey {
			currentFeed = &feeds[i]
			break
		}
	}

	if currentFeed == nil {
		http.Error(w, "Feed not found", http.StatusNotFound)
		return
	}

	data := map[string]interface{}{
		"Session":     session,
		"Feeds":       feeds,
		"CurrentFeed": currentFeed,
	}

	tmpl, ok := h.app.Templates["home.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("home template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.app.Logger.Error().Err(err).Msg("render feed view page")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Helper functions

type contextKey string

const sessionKey contextKey = "session"

// WithSession adds session to context.
func WithSession(ctx context.Context, session *auth.Session) context.Context {
	return context.WithValue(ctx, sessionKey, session)
}

// getSession retrieves session from context (internal use).
func getSession(ctx context.Context) *auth.Session {
	session, _ := ctx.Value(sessionKey).(*auth.Session)
	return session
}

// GetSessionFromContext retrieves session from context (exported for middleware).
func GetSessionFromContext(ctx context.Context) *auth.Session {
	return getSession(ctx)
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
