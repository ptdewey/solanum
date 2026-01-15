package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/patricktcoakley/solanum/internal/web/handlers"
	"github.com/rs/zerolog"
)

// LoggingMiddleware creates a comprehensive logging middleware.
func LoggingMiddleware(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture status code and bytes written
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				bytesWritten:   0,
			}

			// Call the next handler
			next.ServeHTTP(rw, r)

			// Calculate duration
			duration := time.Since(start)

			// Select log level based on status code
			var logEvent *zerolog.Event
			if rw.statusCode >= 500 {
				logEvent = logger.Error()
			} else if rw.statusCode >= 400 {
				logEvent = logger.Warn()
			} else {
				logEvent = logger.Info()
			}

			// Add core fields
			logEvent.
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("query", r.URL.RawQuery).
				Int("status", rw.statusCode).
				Dur("duration", duration).
				Str("client_ip", getClientIP(r)).
				Str("user_agent", r.UserAgent()).
				Int64("bytes_written", rw.bytesWritten).
				Str("proto", r.Proto)

			// Add optional fields only if present
			if referer := r.Referer(); referer != "" {
				logEvent.Str("referer", referer)
			}
			if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
				logEvent.Str("request_id", reqID)
			}
			if contentType := r.Header.Get("Content-Type"); contentType != "" {
				logEvent.Str("content_type", contentType)
			}

			// Get authenticated DID from session if available
			if session := handlers.GetSessionFromContext(r.Context()); session != nil {
				logEvent.Str("user_did", session.DID.String())
			}

			// Log all request headers for debugging malicious traffic
			headers := make(map[string]string)
			for name, values := range r.Header {
				headers[name] = strings.Join(values, ", ")
			}
			logEvent.Interface("headers", headers)

			logEvent.Msg("HTTP request")
		})
	}
}

// getClientIP extracts the real client IP from the request.
// It checks X-Forwarded-For and X-Real-IP headers first (for reverse proxies).
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (comma-separated list)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (w *responseWriter) WriteHeader(status int) {
	w.statusCode = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}
