package main

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/patricktcoakley/solanum/internal/auth"
	"github.com/patricktcoakley/solanum/internal/feed"
	"github.com/patricktcoakley/solanum/internal/routing"
	"github.com/patricktcoakley/solanum/internal/web/handlers"
	"github.com/patricktcoakley/solanum/internal/web/middleware"
	"github.com/patricktcoakley/solanum/public"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

var scopes = []string{
	"atproto",
	"repo:net.solanaceae.solanum.feedCache",
	"repo:net.solanaceae.solanum.feed",
	"repo:net.solanaceae.solanum.readingItem",
	"repo:net.solanaceae.solanum.readingArchive",
	"repo:net.solanaceae.solanum.removedEntries",
	// HACK: this should be 'application/json' once mime type issue is fixed.
	// (PDS shows metadata for blob instead of blob contents with json mimetype)
	"blob:text/plain",
}

func main() {
	// Configure zerolog
	// Set log level from environment (default: info)
	logLevel := os.Getenv("LOG_LEVEL")
	switch logLevel {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info", "":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Use pretty console logging in development, JSON in production
	if os.Getenv("LOG_FORMAT") == "json" {
		// Production: JSON logs
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	} else {
		// Development: pretty console logs
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		})
	}

	log.Info().Msg("Starting Solanum RSS Feed Reader")

	// Get port from env or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Get public root URL for reverse proxy deployments
	// This allows the server to be accessed via a different URL than it's running on
	// e.g., SERVER_PUBLIC_URL=https://solanum.example.com when behind a reverse proxy
	publicURL := os.Getenv("SERVER_PUBLIC_URL")

	// Determine if we should use secure cookies based on the public URL scheme
	// If the public URL uses https://, enable secure cookies
	// Otherwise (http:// or no public URL), disable secure cookies for development
	secureCookies := false
	if publicURL != "" && len(publicURL) >= 8 && publicURL[:8] == "https://" {
		secureCookies = true
	}

	// Initialize SQLite database
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		// Default to XDG data directory or home directory for development
		// This avoids issues when running from read-only locations (e.g., nix run)
		dataDir := os.Getenv("XDG_DATA_HOME")
		if dataDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to get home directory")
			}
			dataDir = filepath.Join(home, ".local", "share")
		}
		dbPath = filepath.Join(dataDir, "solanum", "solanum.db")
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		log.Fatal().Err(err).Str("path", dbPath).Msg("Failed to open database")
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close database")
		}
	}()

	log.Info().Str("path", dbPath).Msg("Database opened")

	authStore, err := auth.NewSQLiteAuthStore(db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize auth store")
	}

	userSessions, err := auth.NewUserSessionStore(db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize user session store")
	}

	// Initialize OAuth configuration
	// For local development, localhost URLs trigger special localhost mode in indigo
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	redirectURI := os.Getenv("OAUTH_REDIRECT_URI")

	if clientID == "" && redirectURI == "" {
		// Use public URL if set, otherwise localhost defaults for development
		if publicURL != "" {
			redirectURI = publicURL + "/oauth/callback"
			clientID = publicURL
			log.Info().
				Str("public_url", publicURL).
				Str("client_id", clientID).
				Str("redirect_uri", redirectURI).
				Msg("Using public URL for OAuth (reverse proxy mode)")
		} else {
			redirectURI = fmt.Sprintf("http://127.0.0.1:%s/oauth/callback", port)
			clientID = fmt.Sprintf("http://127.0.0.1:%s", port)
			log.Info().
				Str("client_id", clientID).
				Str("redirect_uri", redirectURI).
				Msg("Using localhost OAuth mode (for development)")
		}
	} else {
		log.Info().
			Str("client_id", clientID).
			Str("redirect_uri", redirectURI).
			Msg("Using explicit OAuth configuration from environment")
	}

	oauthService := auth.NewOAuthService(clientID, redirectURI, scopes, authStore)

	feedService := feed.NewService()
	log.Info().Msg("Feed service initialized")

	baseTemplate, err := template.ParseFS(public.TemplatesFS, "templates/base.tmpl")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse base template")
	}

	pages := []string{"login.tmpl", "home.tmpl", "feeds.tmpl", "reading_list.tmpl", "archive.tmpl", "import.tmpl", "profile.tmpl"}
	templates := make(map[string]*template.Template)
	for _, page := range pages {
		tmpl, err := template.Must(baseTemplate.Clone()).ParseFS(public.TemplatesFS, "templates/"+page)
		if err != nil {
			log.Fatal().Err(err).Str("page", page).Msg("Failed to parse page template")
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
		Logger:       log.Logger,
		IsProduction: secureCookies,
	}

	// Setup routes
	mux := routing.SetupRoutes(app)

	// Apply middleware (no global CSRF - it's applied per-route in routing.go)
	handler := middleware.Chain(
		middleware.Recover(log.Logger),
		middleware.LoggingMiddleware(log.Logger),
		middleware.SecurityHeaders(secureCookies),
		middleware.Auth(userSessions),
	)(mux)

	// Create server
	server := &http.Server{
		Addr:         "0.0.0.0:" + port,
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
					log.Error().Err(err).Msg("Cleanup expired auth requests")
				}
				if err := userSessions.CleanupExpiredSessions(ctx); err != nil {
					log.Error().Err(err).Msg("Cleanup expired user sessions")
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

		log.Info().Msg("Shutting down server")
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Server shutdown error")
		}
	}()

	// Start server
	log.Info().
		Str("address", "0.0.0.0:"+port).
		Str("url", "http://localhost:"+port).
		Bool("secure_cookies", secureCookies).
		Str("database", dbPath).
		Msg("Starting HTTP server")

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("Server error")
	}
}
