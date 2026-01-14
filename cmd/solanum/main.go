package main

import (
	"context"
	"database/sql"
	"flag"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/patricktcoakley/solanum/internal/auth"
	"github.com/patricktcoakley/solanum/internal/feed"
	"github.com/patricktcoakley/solanum/internal/web/handlers"
	"github.com/patricktcoakley/solanum/internal/web/middleware"
	"github.com/patricktcoakley/solanum/public"
	"github.com/rs/zerolog"
	_ "modernc.org/sqlite"
)

// OAuth scopes
var scopes = []string{
	"atproto",
	"repo:net.solanaceae.solanum.feedCache",
	"repo:net.solanaceae.solanum.feed",
	"repo:net.solanaceae.solanum.readingItem",
}

func main() {
	// Parse flags
	addr := flag.String("addr", ":8080", "HTTP server address")
	dbPath := flag.String("db", "solanum.db", "SQLite database path")
	clientID := flag.String("client-id", "", "OAuth client ID (use 127.0.0.1 URL for development)")
	callbackURL := flag.String("callback-url", "http://127.0.0.1:8080/auth/callback", "OAuth callback URL")
	flag.Parse()

	// Setup logger
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().
		Timestamp().
		Logger()

	// For development, use 127.0.0.1 client ID if not provided (localhost doesn't work for OAuth)
	if *clientID == "" {
		*clientID = "http://127.0.0.1:8080?redirect_uri=" + *callbackURL + "&scope=atproto"
		logger.Info().Str("client_id", *clientID).Msg("using 127.0.0.1 OAuth client ID for development")
	}

	// Open database
	db, err := sql.Open("sqlite", *dbPath+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		logger.Fatal().Err(err).Msg("open database")
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error().Err(err).Msg("failed to close database")
		}
	}()

	// Initialize stores
	authStore, err := auth.NewSQLiteAuthStore(db)
	if err != nil {
		logger.Fatal().Err(err).Msg("init auth store")
	}

	userSessions, err := auth.NewUserSessionStore(db)
	if err != nil {
		logger.Fatal().Err(err).Msg("init user session store")
	}

	feedCache, err := feed.NewCache(db)
	if err != nil {
		logger.Fatal().Err(err).Msg("init feed cache")
	}

	oauthService := auth.NewOAuthService(*clientID, *callbackURL, scopes, authStore)

	// Initialize services
	feedService := feed.NewService(feedCache)

	// Parse templates - parse base first, then each page with the base
	baseTemplate, err := template.ParseFS(public.TemplatesFS, "templates/base.tmpl")
	if err != nil {
		logger.Fatal().Err(err).Msg("parse base template")
	}

	pages := []string{"login.tmpl", "home.tmpl", "feeds.tmpl", "reading_list.tmpl", "archive.tmpl", "import.tmpl"}
	templates := make(map[string]*template.Template)
	for _, page := range pages {
		tmpl, err := template.Must(baseTemplate.Clone()).ParseFS(public.TemplatesFS, "templates/"+page)
		if err != nil {
			logger.Fatal().Err(err).Str("page", page).Msg("parse page template")
		}
		templates[page] = tmpl
	}

	// Create app with dependencies
	app := &handlers.App{
		OAuth:        oauthService,
		AuthStore:    authStore,
		UserSessions: userSessions,
		FeedService:  feedService,
		Templates:    templates,
		Logger:       logger,
	}

	// Create handlers
	authHandler := handlers.NewAuthHandler(app)
	feedHandler := handlers.NewFeedHandler(app)
	readingListHandler := handlers.NewReadingListHandler(app)
	homeHandler := handlers.NewHomeHandler(app)

	// Setup router using stdlib http.ServeMux (Go 1.22+ with method routing)
	mux := http.NewServeMux()

	// Static files
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(public.StaticFS)))

	// Auth routes
	mux.HandleFunc("GET /login", authHandler.LoginPage)
	mux.HandleFunc("POST /auth/login", authHandler.StartAuth)
	mux.HandleFunc("GET /auth/callback", authHandler.Callback)
	mux.HandleFunc("POST /auth/logout", authHandler.Logout)

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

	// Protected routes - Reading List
	mux.HandleFunc("GET /reading-list", readingListHandler.ListItems)
	mux.HandleFunc("GET /reading-list/archive", readingListHandler.ArchivePage)
	mux.HandleFunc("POST /reading-list", readingListHandler.AddItem)
	mux.HandleFunc("POST /reading-list/{rkey}/archive", readingListHandler.ArchiveItem)
	mux.HandleFunc("POST /reading-list/{rkey}/delete", readingListHandler.DeleteItem)

	// Apply middleware
	handler := middleware.Chain(
		middleware.Recover(logger),
		middleware.Logger(logger),
		middleware.CSRF("http://127.0.0.1:8080"), // Trust our own origin
		middleware.Auth(userSessions),
	)(mux)

	// Create server
	server := &http.Server{
		Addr:         *addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start background cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := authStore.CleanupExpiredRequests(ctx); err != nil {
					logger.Error().Err(err).Msg("cleanup expired auth requests")
				}
				if err := userSessions.CleanupExpiredSessions(ctx); err != nil {
					logger.Error().Err(err).Msg("cleanup expired user sessions")
				}
				if err := feedCache.CleanupOldItems(ctx, 30*24*time.Hour); err != nil {
					logger.Error().Err(err).Msg("cleanup old feed items")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		logger.Info().Msg("shutting down server")
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error().Err(err).Msg("server shutdown error")
		}
	}()

	// Start server
	logger.Info().Str("addr", *addr).Msg("starting server")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatal().Err(err).Msg("server error")
	}
}
