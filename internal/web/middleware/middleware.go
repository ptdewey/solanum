// Package middleware provides HTTP middleware for the web application.
package middleware

import (
	"net/http"
	"time"

	"github.com/patricktcoakley/solanum/internal/auth"
	"github.com/patricktcoakley/solanum/internal/web/handlers"
	"github.com/rs/zerolog"
)

// Logger creates a logging middleware.
func Logger(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(ww, r)

			logger.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.status).
				Dur("duration", time.Since(start)).
				Str("remote", r.RemoteAddr).
				Str("user_agent", r.UserAgent()).
				Msg("request")
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Auth creates authentication middleware that loads the user session.
func Auth(sessions *auth.UserSessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("solanum_session")
			if err != nil {
				// No session cookie, continue without session
				next.ServeHTTP(w, r)
				return
			}

			session, err := sessions.GetSession(r.Context(), cookie.Value)
			if err != nil {
				// Invalid or expired session, continue without session
				next.ServeHTTP(w, r)
				return
			}

			// Add session to context
			ctx := handlers.WithSession(r.Context(), session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuth is middleware that requires an authenticated session.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := handlers.GetSessionFromContext(r.Context())
		if session == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CSRF creates CSRF protection middleware using Go 1.25's http.CrossOriginProtection.
func CSRF(trustedOrigins ...string) func(http.Handler) http.Handler {
	// Go 1.25 provides http.CrossOriginProtection
	cop := &http.CrossOriginProtection{}
	for _, origin := range trustedOrigins {
		cop.AddTrustedOrigin(origin)
	}

	return cop.Handler
}

// Chain combines multiple middleware functions.
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// Recover creates panic recovery middleware.
func Recover(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error().
						Interface("panic", err).
						Str("path", r.URL.Path).
						Msg("panic recovered")
					http.Error(w, "Internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
