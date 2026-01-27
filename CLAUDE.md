# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Solanum is an RSS/Atom feed reader built on AT Protocol (ATProto) that stores user data in their Personal Data Server (PDS). It's a Go web application that uses OAuth for authentication and stores feed subscriptions, reading lists, and cached content as lexicon records and blobs in the user's PDS.

## Commands

### Build and Run
```bash
# Run the application directly
just run
# or
go run cmd/solanum/main.go

# Run via Nix (useful for deployment testing)
just nix-run
# or
nix run .#default
```

### Testing
```bash
# Run all tests with coverage
just test
# or
go test ./... -cover -coverprofile=cover.out

# Run tests for a specific package
go test ./internal/feed -v
```

## Architecture Overview

### Data Storage Strategy
Solanum stores data in the user's PDS using custom lexicons. There are two storage patterns:

1. **Record-per-item** (for small collections):
   - `net.solanaceae.solanum.feed` - Feed subscriptions
   - `net.solanaceae.solanum.readingItem` - Active reading list items

2. **Blob-based storage** (for larger collections):
   - `net.solanaceae.solanum.feedCache` - Cached feed entries (up to 200 items per blob)
   - `net.solanaceae.solanum.removedEntries` - List of removed entry URLs
   - `net.solanaceae.solanum.readingArchive` - Archived reading items

The blob-based approach stores a record with a `BlobRef` pointing to a JSON blob. This avoids hitting per-record limits and improves performance for large datasets. Blobs are limited to 1MB by AT Protocol spec.

### Authentication Flow
Uses AT Protocol OAuth with PKCE:
1. User initiates login via `/oauth/login`
2. OAuth flow redirects to user's PDS for authorization
3. Callback at `/oauth/callback` completes the flow
4. Session stored in SQLite (`oauth_sessions` table)
5. Middleware (`internal/web/middleware`) validates sessions on protected routes

Session management uses the Bluesky Indigo library's `oauth.ClientAuthStore` interface, implemented by `SQLiteAuthStore` in `internal/auth/auth.go`.

### Package Structure

- **`cmd/solanum/main.go`**: Application entrypoint
  - Initializes database, templates, services
  - Sets up OAuth configuration (supports localhost dev mode and reverse proxy deployments)
  - Configures middleware chain
  - Handles graceful shutdown

- **`internal/auth`**: OAuth and session management
  - `SQLiteAuthStore`: Implements `oauth.ClientAuthStore` for Indigo OAuth
  - `UserSessionStore`: Application session tracking
  - Tables: `oauth_sessions`, `oauth_auth_requests`, `user_sessions`

- **`internal/pds`**: AT Protocol PDS client
  - `Client`: CRUD operations for lexicon records and blobs
  - Type definitions for all custom lexicons
  - Slingshot proxy integration for blob uploads
  - Methods: `ListFeeds`, `CreateFeed`, `UpdateFeed`, `DeleteFeed`, `GetFeedCache`, `UpdateFeedCache`, etc.

- **`internal/feed`**: RSS/Atom feed parsing
  - Uses `gofeed` library for parsing
  - SSRF protection: validates URLs and blocks private IPs
  - Feed autodiscovery from HTML pages
  - `Service` type provides `FetchFeed` and `DiscoverFeeds` methods

- **`internal/web/handlers`**: HTTP handlers
  - `App` struct holds shared dependencies (OAuth, AuthStore, FeedService, Templates)
  - Handler types: `AuthHandler`, `FeedHandler`, `ReadingListHandler`, `HomeHandler`, `ProfileHandler`
  - All handlers are methods on these types

- **`internal/web/middleware`**: HTTP middleware
  - `Auth`: Session validation
  - `SecurityHeaders`: Security headers (CSP, HSTS, etc.)
  - `LoggingMiddleware`: Request/response logging
  - `Recover`: Panic recovery

- **`internal/routing`**: Route configuration
  - Uses Go 1.22+ `http.ServeMux` with method-based routing
  - CSRF protection via `http.NewCrossOriginProtection()` on state-changing routes
  - Static file serving from embedded `public.StaticFS`

- **`lexicons/`**: JSON schema definitions for custom AT Protocol lexicons

- **`public/`**: Embedded static assets and templates
  - Accessed via `public.StaticsFS` and `public.TemplatesFS`
  - Templates use Go's `html/template` package

### Configuration
Environment variables (see `cmd/solanum/main.go:38-154` and `module.nix`):
- `PORT`: Server port (default: 8080)
- `DB_PATH`: SQLite database path (default: `$XDG_DATA_HOME/solanum/solanum.db`)
- `LOG_LEVEL`: debug, info, warn, error (default: info)
- `LOG_FORMAT`: json or pretty (default: json in production)
- `SERVER_PUBLIC_URL`: Public URL for reverse proxy deployments (enables secure cookies)
- `OAUTH_CLIENT_ID`: OAuth client ID (auto-derived from `SERVER_PUBLIC_URL` if not set)
- `OAUTH_REDIRECT_URI`: OAuth redirect URI (auto-derived from `SERVER_PUBLIC_URL` if not set)

### Database
SQLite with WAL mode and foreign keys enabled. Tables are created via migration functions in each package:
- `internal/auth/auth.go`: OAuth tables
- `internal/pds`: No local storage (all in PDS)
- `internal/feed`: No local storage

### Import/Export
Supports importing feed subscriptions from Leaflet's `pub.leaflet.graph.subscription` lexicon. The import flow:
1. Fetch subscriptions from user's PDS (`/feeds/import/leaflet/fetch`)
2. For each subscription, fetch the `pub.leaflet.publication` record to get RSS URL
3. User selects which feeds to import
4. Create `net.solanaceae.solanum.feed` records in user's PDS

### Security Considerations
- SSRF protection in feed fetching (see `internal/feed/feed.go:38-75`)
- CSRF protection on all state-changing routes
- Secure cookies when `SERVER_PUBLIC_URL` uses HTTPS
- Security headers middleware
- Input validation on all user-provided URLs

## NixOS Module
The project includes a NixOS module (`module.nix`) for deployment. Configure with `services.solanum-rss.enable = true` and set `settings.serverPublicUrl` for reverse proxy deployments.
