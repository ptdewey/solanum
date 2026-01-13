// Package handlers provides HTTP handlers for the web application.
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/patricktcoakley/solanum/internal/auth"
	"github.com/patricktcoakley/solanum/internal/feed"
	"github.com/patricktcoakley/solanum/internal/pds"
	"github.com/rs/zerolog"
)

const sessionCookieName = "solanum_session"

// App holds application dependencies for handlers.
type App struct {
	OAuth        *auth.OAuthService
	AuthStore    *auth.SQLiteAuthStore
	UserSessions *auth.UserSessionStore
	FeedService  *feed.Service
	Templates    map[string]*template.Template
	Logger       zerolog.Logger
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
		http.Error(w, "Failed to start authentication: "+err.Error(), http.StatusInternalServerError)
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
		http.Error(w, "Authentication failed: "+errCode, http.StatusBadRequest)
		return
	}

	if state == "" || code == "" || iss == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	sessData, err := h.app.OAuth.ProcessCallback(r.Context(), state, code, iss)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("complete auth failed")
		http.Error(w, "Authentication failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create browser session cookie
	cookieID := generateSessionID()

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
		Secure:   r.TLS != nil,
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
	// Start with status message
	if len(available) == 0 && len(failed) == 0 {
		w.Write([]byte(`<div class="empty">All your Leaflet subscriptions have already been imported!</div>`))
		return
	}

	// Available feeds section
	if len(available) > 0 {
		w.Write([]byte(`<form action="/feeds/import/leaflet/import" method="POST">`))
		w.Write([]byte(`<div class="select-actions"><button type="button" onclick="selectAll()">Select All</button> | <button type="button" onclick="selectNone()">Select None</button></div>`))
		w.Write([]byte(`<div class="import-list">`))

		for _, feed := range available {
			html := `<label class="import-item">
				<input type="checkbox" class="import-checkbox" name="feeds" value="` + feed.RSSURL + `" checked>
				<div class="import-item-info">
					<div class="import-item-title">` + template.HTMLEscapeString(feed.Title) + `</div>
					<div class="import-item-url">` + template.HTMLEscapeString(feed.RSSURL) + `</div>
				</div>
			</label>`
			w.Write([]byte(html))
		}

		w.Write([]byte(`</div>`))
		w.Write([]byte(`<div class="import-actions">`))
		w.Write([]byte(`<button type="submit" class="btn">Import Selected</button>`))
		w.Write([]byte(`<button type="button" class="btn btn-secondary" onclick="document.getElementById('import-modal').classList.remove('show')">Cancel</button>`))
		w.Write([]byte(`</div></form>`))
	}

	// Already imported message
	if alreadyImported > 0 {
		html := `<p style="color: var(--muted); margin-top: 1rem; font-size: 0.875rem;">` +
			template.HTMLEscapeString(strconv.Itoa(alreadyImported)) + ` subscription(s) already imported.</p>`
		w.Write([]byte(html))
	}

	// Failed section
	if len(failed) > 0 {
		w.Write([]byte(`<div class="error-section">`))
		w.Write([]byte(`<h4>Could not resolve (` + template.HTMLEscapeString(strconv.Itoa(len(failed))) + `)</h4>`))
		w.Write([]byte(`<p style="font-size: 0.875rem; color: var(--muted); margin-bottom: 0.5rem;">These publications may have been deleted or are unavailable.</p>`))
		w.Write([]byte(`<div class="import-list" style="max-height: 150px;">`))

		for _, feed := range failed {
			title := feed.Title
			if title == "" {
				title = feed.Publication
			}
			html := `<div class="import-item import-item-error">
				<span class="error-icon">✗</span>
				<div class="import-item-info">
					<div class="import-item-title">` + template.HTMLEscapeString(title) + `</div>
					<div class="import-item-url">` + template.HTMLEscapeString(feed.Error) + `</div>
				</div>
			</div>`
			w.Write([]byte(html))
		}

		w.Write([]byte(`</div></div>`))
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

		h.app.Logger.Info().Str("url", feed.URL).Msg("fetching feed")

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
			cacheItem := pds.FeedCacheItem{
				ID:          item.ID,
				FeedURL:     feed.URL,
				FeedTitle:   feedTitle,
				Title:       item.Title,
				Description: item.Description,
				Link:        item.Link,
				Author:      item.Author,
				Published:   item.Published,
				Content:     item.Content,
			}
			allItems = append(allItems, cacheItem)
		}
	}

	h.app.Logger.Info().Int("totalItems", len(allItems)).Msg("total items fetched from all feeds")

	// Limit to most recent 200 items total
	if len(allItems) > 200 {
		// Sort by published date descending
		// (simplified - items are already roughly sorted by feed)
		allItems = allItems[:200]
	}

	h.app.Logger.Info().
		Int("totalItems", len(allItems)).
		Int("feedsCount", len(feeds)).
		Msg("PDS blob: populating cache with feed items")

	// Create cache data JSON
	cacheData := pds.FeedCacheData{
		LastUpdated: time.Now().UTC(),
		Items:       allItems,
	}

	// Log first few items for debugging
	if len(allItems) > 0 {
		h.app.Logger.Info().
			Str("firstItemTitle", allItems[0].Title).
			Str("firstItemFeed", allItems[0].FeedTitle).
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
		Int("items", len(allItems)).
		Int("feeds", len(feeds)).
		Msg("PDS blob: uploading feed cache to PDS")
	blobRef, err := pdsClient.UploadBlob(r.Context(), jsonData, "application/json")
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
		ItemCount:   len(allItems),
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
		Int("items", len(allItems)).
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
	blobData, mimeType, err := pdsClient.GetBlob(r.Context(), cache.Blob.Ref.Link)
	if err != nil {
		h.app.Logger.Error().Err(err).Str("cid", cache.Blob.Ref.Link).Msg("get blob")

		// Check if this is the PDS file stream bug
		if pds.IsFileStreamError(err) {
			h.app.Logger.Warn().
				Str("cid", cache.Blob.Ref.Link).
				Msg("PDS returned file stream object instead of blob data - retrying once")

			// Wait briefly and retry once (in case it's a race condition)
			time.Sleep(500 * time.Millisecond)
			blobData, mimeType, err = pdsClient.GetBlob(r.Context(), cache.Blob.Ref.Link)
			if err != nil {
				h.app.Logger.Error().Err(err).Str("cid", cache.Blob.Ref.Link).Msg("get blob retry failed")

				// Still failing - delete the corrupted cache record
				h.app.Logger.Warn().
					Str("oldCid", cache.Blob.Ref.Link).
					Msg("PDS blob consistently returns file stream, deleting cache record")

				if delErr := pdsClient.DeleteFeedCache(r.Context()); delErr != nil {
					h.app.Logger.Error().Err(delErr).Msg("failed to delete corrupted cache")
				}

				// Return empty cache - user needs to refresh
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"exists": false,
					"items":  []pds.FeedCacheItem{},
					"error":  "blob_corrupted",
				})
				return
			}

			h.app.Logger.Info().
				Str("cid", cache.Blob.Ref.Link).
				Msg("retry succeeded - blob data retrieved")
		} else {
			http.Error(w, "Failed to load cache", http.StatusInternalServerError)
			return
		}
	}

	if mimeType != "application/json" {
		h.app.Logger.Error().Str("mimeType", mimeType).Msg("unexpected blob mime type")
		http.Error(w, "Invalid cache format", http.StatusInternalServerError)
		return
	}

	// Parse cache data
	var cacheData pds.FeedCacheData
	if err := json.Unmarshal(blobData, &cacheData); err != nil {
		h.app.Logger.Error().Err(err).Msg("unmarshal cache data")
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

	// Return cache data
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"exists":      true,
		"lastUpdated": cacheData.LastUpdated,
		"items":       cacheData.Items,
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

	// Parse query parameters
	query := r.URL.Query()
	search := query.Get("q")
	pageStr := query.Get("page")
	page := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
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

	// Create feed URL to title map
	feedTitleMap := make(map[string]string)
	feedURLs := make([]string, 0, len(feeds))
	for _, f := range feeds {
		if f.IsActive {
			feedURLs = append(feedURLs, f.URL)
			feedTitleMap[f.URL] = f.Title
		}
	}

	// Get total count for pagination
	totalItems, err := h.app.FeedService.CountItems(r.Context(), feedURLs, search)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("count items")
		totalItems = 0
	}

	totalPages := (totalItems + itemsPerPage - 1) / itemsPerPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * itemsPerPage

	// Get paginated items from cache
	items, err := h.app.FeedService.GetRecentItemsPaginated(r.Context(), feedURLs, search, itemsPerPage, offset)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("get recent items")
		items = nil
	}

	h.app.Logger.Info().
		Int("itemsRetrieved", len(items)).
		Int("feedCount", len(feedURLs)).
		Str("source", "local_cache").
		Msg("Loaded feed items from local cache")

	// Convert to view models with feed titles
	itemViews := make([]FeedItemView, len(items))
	for i, item := range items {
		feedTitle := feedTitleMap[item.FeedURL]
		if feedTitle == "" {
			feedTitle = item.FeedURL
		}
		itemViews[i] = FeedItemView{
			FeedTitle:   feedTitle,
			Title:       item.Title,
			Description: item.Description,
			Link:        item.Link,
			Author:      item.Author,
			Published:   item.Published,
		}
	}

	data := map[string]interface{}{
		"Session":     session,
		"Feeds":       feeds,
		"Items":       itemViews,
		"Search":      search,
		"Page":        page,
		"TotalPages":  totalPages,
		"TotalItems":  totalItems,
		"HasPrevPage": page > 1,
		"HasNextPage": page < totalPages,
		"PrevPage":    page - 1,
		"NextPage":    page + 1,
		"BasePath":    "/",
	}

	tmpl, ok := h.app.Templates["home.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("home template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// For htmx requests, only render the results partial
	templateName := "base"
	if r.Header.Get("HX-Request") == "true" {
		templateName = "results"
	}

	if err := tmpl.ExecuteTemplate(w, templateName, data); err != nil {
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

	// Parse query parameters
	query := r.URL.Query()
	search := query.Get("q")
	pageStr := query.Get("page")
	page := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
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
	for _, f := range feeds {
		if f.RKey == feedRKey {
			currentFeed = &f
			break
		}
	}

	if currentFeed == nil {
		http.Error(w, "Feed not found", http.StatusNotFound)
		return
	}

	feedURLs := []string{currentFeed.URL}

	// Get total count for pagination
	totalItems, err := h.app.FeedService.CountItems(r.Context(), feedURLs, search)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("count items")
		totalItems = 0
	}

	totalPages := (totalItems + itemsPerPage - 1) / itemsPerPage
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * itemsPerPage

	// Get paginated items from cache
	items, err := h.app.FeedService.GetRecentItemsPaginated(r.Context(), feedURLs, search, itemsPerPage, offset)
	if err != nil {
		h.app.Logger.Error().Err(err).Msg("get feed items")
		items = nil
	}

	// Convert to view models with feed title
	itemViews := make([]FeedItemView, len(items))
	for i, item := range items {
		itemViews[i] = FeedItemView{
			FeedTitle:   currentFeed.Title,
			Title:       item.Title,
			Description: item.Description,
			Link:        item.Link,
			Author:      item.Author,
			Published:   item.Published,
		}
	}

	data := map[string]interface{}{
		"Session":     session,
		"Feeds":       feeds,
		"Items":       itemViews,
		"CurrentFeed": currentFeed,
		"Search":      search,
		"Page":        page,
		"TotalPages":  totalPages,
		"TotalItems":  totalItems,
		"HasPrevPage": page > 1,
		"HasNextPage": page < totalPages,
		"PrevPage":    page - 1,
		"NextPage":    page + 1,
		"BasePath":    "/feeds/" + feedRKey + "/view",
	}

	tmpl, ok := h.app.Templates["home.tmpl"]
	if !ok {
		h.app.Logger.Error().Msg("home template not found")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// For htmx requests, only render the results partial
	templateName := "base"
	if r.Header.Get("HX-Request") == "true" {
		templateName = "results"
	}

	if err := tmpl.ExecuteTemplate(w, templateName, data); err != nil {
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

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
