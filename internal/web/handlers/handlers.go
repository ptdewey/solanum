// Package handlers provides HTTP handlers for the web application.
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

	// Refresh feed items in background
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := h.app.FeedService.RefreshFeed(ctx, feedURL); err != nil {
			h.app.Logger.Error().Err(err).Str("url", feedURL).Msg("refresh feed")
		}
	}()

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

		// Refresh feed items in background
		go func(url string) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := h.app.FeedService.RefreshFeed(ctx, url); err != nil {
				h.app.Logger.Error().Err(err).Str("url", url).Msg("refresh feed")
			}
		}(rssURL)
	}

	h.app.Logger.Info().Int("imported", imported).Int("selected", len(feedURLs)).Msg("leaflet import complete")
	http.Redirect(w, r, "/feeds", http.StatusFound)
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

	// Get feed URLs for recent items query
	feedURLs := make([]string, 0, len(feeds))
	for _, f := range feeds {
		if f.IsActive {
			feedURLs = append(feedURLs, f.URL)
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

	data := map[string]interface{}{
		"Session":     session,
		"Feeds":       feeds,
		"Items":       items,
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

	data := map[string]interface{}{
		"Session":     session,
		"Feeds":       feeds,
		"Items":       items,
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
