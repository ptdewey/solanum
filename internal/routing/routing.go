// Package routing handles HTTP route configuration.
package routing

import (
	"io/fs"
	"net/http"

	"github.com/patricktcoakley/solanum/internal/web/handlers"
	"github.com/patricktcoakley/solanum/public"
)

// SetupRoutes configures all HTTP routes for the application.
func SetupRoutes(app *handlers.App) *http.ServeMux {
	// Create handlers
	authHandler := handlers.NewAuthHandler(app)
	feedHandler := handlers.NewFeedHandler(app)
	readingListHandler := handlers.NewReadingListHandler(app)
	homeHandler := handlers.NewHomeHandler(app)
	profileHandler := handlers.NewProfileHandler(app)

	// Setup router using stdlib http.ServeMux (Go 1.22+ with method routing)
	mux := http.NewServeMux()

	// Create CrossOriginProtection for CSRF protection on state-changing routes
	cop := http.NewCrossOriginProtection()

	// Static files with proper MIME type handling
	// Create a sub-filesystem from the 'static' directory within StaticFS
	staticFS, err := fs.Sub(public.StaticFS, "static")
	if err != nil {
		panic("failed to create static sub-filesystem: " + err.Error())
	}
	staticHandler := http.StripPrefix("/static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /static/", func(w http.ResponseWriter, r *http.Request) {
		staticHandler.ServeHTTP(w, r)
	})

	// OAuth client metadata (required for public OAuth clients)
	mux.HandleFunc("GET /client-metadata.json", authHandler.ClientMetadata)
	mux.HandleFunc("GET /.well-known/oauth-client-metadata", authHandler.ClientMetadata)

	// Auth routes (OAuth flow doesn't need CSRF - uses state parameter and PKCE)
	mux.HandleFunc("GET /login", authHandler.LoginPage)
	mux.HandleFunc("POST /oauth/login", authHandler.StartAuth)
	mux.HandleFunc("GET /oauth/callback", authHandler.Callback)
	mux.Handle("POST /oauth/logout", cop.Handler(http.HandlerFunc(authHandler.Logout)))

	// Protected routes - Home
	mux.HandleFunc("GET /", homeHandler.Home)

	// Protected routes - Profile
	mux.HandleFunc("GET /profile", profileHandler.ProfilePage)

	// Protected routes - Feeds (GET requests don't need CSRF)
	mux.HandleFunc("GET /feeds", feedHandler.ListFeeds)
	mux.Handle("POST /feeds", cop.Handler(http.HandlerFunc(feedHandler.AddFeed)))
	mux.HandleFunc("GET /feeds/import", feedHandler.ImportPage)
	mux.HandleFunc("GET /feeds/import/leaflet/fetch", feedHandler.FetchLeafletFeeds)
	mux.Handle("POST /feeds/import/leaflet/import", cop.Handler(http.HandlerFunc(feedHandler.ImportSelectedLeafletFeeds)))
	mux.Handle("POST /feeds/refresh", cop.Handler(http.HandlerFunc(feedHandler.RefreshFeeds)))
	mux.HandleFunc("GET /feeds/cache", feedHandler.GetFeedCache)
	mux.HandleFunc("GET /feeds/cache/debug", feedHandler.DebugFeedCache)
	mux.Handle("POST /feeds/{rkey}/delete", cop.Handler(http.HandlerFunc(feedHandler.DeleteFeed)))
	mux.HandleFunc("GET /feeds/{rkey}/view", homeHandler.FeedView)

	// Protected routes - Feed Entry Actions
	mux.Handle("POST /entries/remove", cop.Handler(http.HandlerFunc(feedHandler.RemoveEntry)))
	mux.Handle("POST /entries/mark-read", cop.Handler(http.HandlerFunc(feedHandler.MarkEntryAsRead)))

	// Protected routes - Reading List
	mux.HandleFunc("GET /reading-list", readingListHandler.ListItems)
	mux.HandleFunc("GET /reading-list/archive", readingListHandler.ArchivePage)
	mux.Handle("POST /reading-list", cop.Handler(http.HandlerFunc(readingListHandler.AddItem)))
	mux.Handle("POST /reading-list/{rkey}/archive", cop.Handler(http.HandlerFunc(readingListHandler.ArchiveItem)))
	mux.Handle("POST /reading-list/{rkey}/delete", cop.Handler(http.HandlerFunc(readingListHandler.DeleteItem)))
	mux.Handle("POST /reading-list/archive/delete", cop.Handler(http.HandlerFunc(readingListHandler.DeleteArchivedItem)))

	return mux
}
