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

	// Setup router using stdlib http.ServeMux (Go 1.22+ with method routing)
	mux := http.NewServeMux()

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

	// Auth routes
	mux.HandleFunc("GET /login", authHandler.LoginPage)
	mux.HandleFunc("POST /oauth/login", authHandler.StartAuth)
	mux.HandleFunc("GET /oauth/callback", authHandler.Callback)
	mux.HandleFunc("POST /oauth/logout", authHandler.Logout)

	// Protected routes - Home
	mux.HandleFunc("GET /", homeHandler.Home)

	// Protected routes - Feeds
	mux.HandleFunc("GET /feeds", feedHandler.ListFeeds)
	mux.HandleFunc("POST /feeds", feedHandler.AddFeed)
	mux.HandleFunc("GET /feeds/import", feedHandler.ImportPage)
	mux.HandleFunc("GET /feeds/import/leaflet/fetch", feedHandler.FetchLeafletFeeds)
	mux.HandleFunc("POST /feeds/import/leaflet/import", feedHandler.ImportSelectedLeafletFeeds)
	mux.HandleFunc("POST /feeds/refresh", feedHandler.RefreshFeeds)
	mux.HandleFunc("GET /feeds/cache", feedHandler.GetFeedCache)
	mux.HandleFunc("GET /feeds/cache/debug", feedHandler.DebugFeedCache)
	mux.HandleFunc("POST /feeds/{rkey}/delete", feedHandler.DeleteFeed)
	mux.HandleFunc("GET /feeds/{rkey}/view", homeHandler.FeedView)

	// Protected routes - Feed Entry Actions
	mux.HandleFunc("POST /entries/remove", feedHandler.RemoveEntry)
	mux.HandleFunc("POST /entries/mark-read", feedHandler.MarkEntryAsRead)

	// Protected routes - Reading List
	mux.HandleFunc("GET /reading-list", readingListHandler.ListItems)
	mux.HandleFunc("GET /reading-list/archive", readingListHandler.ArchivePage)
	mux.HandleFunc("POST /reading-list", readingListHandler.AddItem)
	mux.HandleFunc("POST /reading-list/{rkey}/archive", readingListHandler.ArchiveItem)
	mux.HandleFunc("POST /reading-list/{rkey}/delete", readingListHandler.DeleteItem)
	mux.HandleFunc("POST /reading-list/archive/delete", readingListHandler.DeleteArchivedItem)

	return mux
}
