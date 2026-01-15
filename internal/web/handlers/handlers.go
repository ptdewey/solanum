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

// LoginPage renders the login form.
func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	sessData, err := h.app.OAuth.ProcessCallback(r.Context(), state, code, iss)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("complete auth failed")
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

	// Get handle by resolving DID
	handle := sessData.AccountDID.String() // Fallback to DID
	// The handle would normally be resolved from identity, but for now we use DID

	if err := h.app.UserSessions.CreateSession(r.Context(), cookieID, sessData.AccountDID, handle, sessData.SessionID, 7*24*time.Hour); err != nil {
		h.app.Logger.Error().Err(err).Msg("create user session failed")
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Suppress unused variable warning
	_ = sess

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.app.IsProduction, // Always secure in production, even behind reverse proxy
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})

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

// FetchLeafletFeeds fetches and resolves Leaflet subscriptions, returning HTML partial.
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

	// Get existing feeds to mark already imported ones
	existingFeeds, err := pdsClient.ListFeeds(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("list feeds")
		// Non-fatal, continue without duplicate detection
		existingFeeds = []pds.Feed{}
	}

	existingURLs := make(map[string]bool)
	for _, feed := range existingFeeds {
		existingURLs[feed.URL] = true
	}

	// Resolve each subscription
	var available []LeafletFeedResult
	var failed []LeafletFeedResult
	var alreadyImported int

	for _, sub := range leafletSubs {
		rssURL, err := pdsClient.GetLeafletFeedRSSURL(r.Context(), sub.Publication)
		if err != nil {
			failed = append(failed, LeafletFeedResult{
				Publication: sub.Publication,
				Title:       sub.Title,
				Error:       err.Error(),
			})
			continue
		}

		if existingURLs[rssURL] {
			alreadyImported++
			continue
		}

		// Try to get title from feed metadata
		title := sub.Title
		if title == "" {
			metadata, err := h.app.FeedService.FetchMetadata(r.Context(), rssURL)
			if err == nil && metadata.Title != "" {
				title = metadata.Title
			} else {
				title = rssURL
			}
		}

		available = append(available, LeafletFeedResult{
			Publication: sub.Publication,
			Title:       title,
			RSSURL:      rssURL,
		})
	}

	// Render the results as HTML partial
	w.Header().Set("Content-Type", "text/html")
	h.renderLeafletResults(w, available, failed, alreadyImported)
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

	feedURLs := r.Form["feeds"]
	if len(feedURLs) == 0 {
		http.Redirect(w, r, "/feeds", http.StatusFound)
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
	for _, rssURL := range feedURLs {
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

	h.app.Logger.Info().Int("imported", imported).Int("selected", len(feedURLs)).Msg("leaflet import complete")
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

	h.app.Logger.Info().Str("url", entryURL).Msg("Entry marked as removed")

	// Return success response for HTMX
	w.WriteHeader(http.StatusOK)
}

// MarkEntryAsRead marks an entry as read by creating an archived reading list item.
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

	// Create reading item that is immediately archived
	now := time.Now().UTC()
	item := &pds.ReadingItem{
		URL:         entryURL,
		Title:       title,
		Description: description,
		IsArchived:  true,
		ArchivedAt:  &now,
	}

	_, _, err = pdsClient.CreateReadingItem(r.Context(), item)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("create archived reading item")
		http.Error(w, "Failed to mark as read", http.StatusInternalServerError)
		return
	}

	// Also add to removed entries
	if err := pdsClient.AddRemovedEntry(r.Context(), entryURL); err != nil {
		h.app.Logger.Warn().Err(err).Str("url", entryURL).Msg("failed to add to removed entries, but reading item was created")
	}

	h.app.Logger.Info().Str("url", entryURL).Msg("Entry marked as read and archived")

	// Return success response for HTMX
	w.WriteHeader(http.StatusOK)
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

	// Debug: Log the scopes from the session data
	h.app.Logger.Info().
		Strs("scopes", oauthSess.Data.Scopes).
		Msg("OAuth session scopes")

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

		h.app.Logger.Info().Str("url", feed.URL).Msg("fetching feed")

		// Fetch feed items for the PDS blob cache
		metadata, items, err := h.app.FeedService.FetchFeed(r.Context(), feed.URL)
		if err != nil {
			h.app.Logger.Error().Err(err).Str("url", feed.URL).Msg("fetch feed")
			continue
		}

		h.app.Logger.Info().
			Str("url", feed.URL).
			Int("itemCount", len(items)).
			Msg("fetched feed items")

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

	h.app.Logger.Info().Int("totalItems", len(allItems)).Msg("total items fetched from all feeds")

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

	h.app.Logger.Info().
		Int("originalCount", len(allItems)).
		Int("filteredCount", len(filteredItems)).
		Int("removedCount", len(removedURLs)).
		Msg("Filtered removed entries before caching")

	// Sort filtered items by published date (most recent first)
	sort.Slice(filteredItems, func(i, j int) bool {
		return filteredItems[i].Published.After(filteredItems[j].Published)
	})

	// Limit to most recent 200 items total
	if len(filteredItems) > 200 {
		filteredItems = filteredItems[:200]
	}

	h.app.Logger.Info().
		Int("totalItems", len(filteredItems)).
		Int("feedsCount", len(feeds)).
		Msg("PDS blob: populating cache with feed items")

	// Create cache data JSON
	cacheData := pds.FeedCacheData{
		LastUpdated: time.Now().UTC(),
		Items:       filteredItems,
	}

	// Log first few items for debugging
	if len(filteredItems) > 0 {
		h.app.Logger.Info().
			Str("firstItemTitle", filteredItems[0].Title).
			Str("firstItemFeed", filteredItems[0].FeedTitle).
			Msg("sample item from cache")
	}

	jsonData, err := json.Marshal(cacheData)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("marshal cache data")
		http.Error(w, "Failed to create cache", http.StatusInternalServerError)
		return
	}

	// Upload blob to PDS
	h.app.Logger.Info().
		Int("blobSize", len(jsonData)).
		Int("items", len(filteredItems)).
		Int("feeds", len(feeds)).
		Msg("PDS blob: uploading feed cache to PDS")
	// HACK: once pds json blob mimetype issue is fixed, swap to 'application/json'
	blobRef, err := pdsClient.UploadBlob(r.Context(), jsonData, "text/plain")
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("upload blob")
		http.Error(w, "Failed to upload cache", http.StatusInternalServerError)
		return
	}

	h.app.Logger.Info().
		Str("cid", blobRef.Ref.Link).
		Int("size", blobRef.Size).
		Str("mimeType", blobRef.MimeType).
		Msg("blob uploaded successfully")

	// Create/update cache record
	cache := &pds.FeedCache{
		Blob:        *blobRef,
		LastUpdated: time.Now().UTC(),
		ItemCount:   len(filteredItems),
		FeedCount:   len(feeds),
	}

	h.app.Logger.Info().
		Str("collection", pds.FeedCacheNSID).
		Str("rkey", "self").
		Interface("blobRef", blobRef).
		Msg("creating feed cache record")

	cid, err := pdsClient.CreateFeedCache(r.Context(), cache)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("create feed cache")
		http.Error(w, "Failed to save cache", http.StatusInternalServerError)
		return
	}

	h.app.Logger.Info().
		Str("recordCID", cid).
		Int("items", len(filteredItems)).
		Int("feeds", len(feeds)).
		Msg("feed cache record created successfully")

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
	h.app.Logger.Info().
		Str("cid", cache.Blob.Ref.Link).
		Str("did", session.DID.String()).
		Msg("fetching blob from PDS")

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

	h.app.Logger.Info().
		Int("blobDataSize", len(blobData)).
		Str("mimeType", mimeType).
		Str("cid", cache.Blob.Ref.Link).
		Msg("blob data received successfully")

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

	h.app.Logger.Info().
		Int("blobSize", len(blobData)).
		Int("itemCount", len(cacheData.Items)).
		Str("cid", cache.Blob.Ref.Link).
		Msg("✓ Using PDS blob to populate feed cache")

	// Log a sample of items for verification
	if len(cacheData.Items) > 0 {
		h.app.Logger.Info().
			Str("firstItem", cacheData.Items[0].Title).
			Str("feedTitle", cacheData.Items[0].FeedTitle).
			Msg("Sample item from PDS blob cache")
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

	h.app.Logger.Info().
		Int("originalCount", len(cacheData.Items)).
		Int("filteredCount", len(filteredItems)).
		Int("removedCount", len(removedURLs)).
		Msg("Filtered removed entries from cache")

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

	// Separate active and archived items
	var active, archived []pds.ReadingItem
	for _, item := range items {
		if item.IsArchived {
			archived = append(archived, item)
		} else {
			active = append(active, item)
		}
	}

	data := map[string]interface{}{
		"Session":     session,
		"Active":      active,
		"HasArchived": len(archived) > 0,
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

// ArchivePage shows archived reading list items.
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
	items, err := pdsClient.ListReadingItems(r.Context())
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("list reading items")
		http.Error(w, "Failed to load archive", http.StatusInternalServerError)
		return
	}

	// Filter only archived items
	var archived []pds.ReadingItem
	for _, item := range items {
		if item.IsArchived {
			archived = append(archived, item)
		}
	}

	data := map[string]interface{}{
		"Session":  session,
		"Archived": archived,
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
