// Package feed provides RSS/Atom feed parsing and local caching.
package feed

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mmcdole/gofeed"
	"golang.org/x/net/html"
)

var (
	ErrFeedNotFound = errors.New("feed not found")
	ErrInvalidURL   = errors.New("invalid feed URL")
	ErrFetchFailed  = errors.New("failed to fetch feed")
	ErrSSRFBlocked  = errors.New("URL is blocked for security reasons")
)

// Item represents a single item/post from an RSS/Atom feed.
type Item struct {
	ID          string
	FeedURL     string
	Title       string
	Description string
	Link        string
	Author      string
	Published   time.Time
	Updated     time.Time
	Content     string
}

// ValidateFeedURL checks if a URL is safe to fetch (SSRF protection).
func ValidateFeedURL(feedURL string) error {
	parsedURL, err := url.Parse(feedURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	// Only allow http and https schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("%w: only http and https schemes allowed", ErrSSRFBlocked)
	}

	// Get hostname
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return fmt.Errorf("%w: missing hostname", ErrInvalidURL)
	}

	// Block localhost and private IP ranges
	if isPrivateOrLocalhost(hostname) {
		return fmt.Errorf("%w: localhost and private IPs are not allowed", ErrSSRFBlocked)
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("%w: cannot resolve hostname", ErrInvalidURL)
	}

	// Check all resolved IPs
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("%w: hostname resolves to private IP", ErrSSRFBlocked)
		}
	}

	return nil
}

// isPrivateOrLocalhost checks if a hostname is localhost or a private address.
func isPrivateOrLocalhost(hostname string) bool {
	hostname = strings.ToLower(hostname)

	// Check for localhost variants
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" ||
		strings.HasPrefix(hostname, "localhost.") || strings.HasPrefix(hostname, "127.") ||
		hostname == "0.0.0.0" {
		return true
	}

	// Check for AWS/GCP/Azure metadata endpoints
	metadataEndpoints := []string{
		"169.254.169.254", // AWS, Azure, GCP metadata
		"metadata.google.internal",
		"169.254.170.2", // AWS ECS
	}
	for _, endpoint := range metadataEndpoints {
		if hostname == endpoint {
			return true
		}
	}

	return false
}

// isPrivateIP checks if an IP address is in a private range.
func isPrivateIP(ip net.IP) bool {
	// Private IPv4 ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local (AWS metadata)
		"224.0.0.0/4",    // Multicast
		"240.0.0.0/4",    // Reserved
	}

	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			return true
		}
	}

	// Check for IPv6 private addresses
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}

// Metadata contains parsed feed metadata.
type Metadata struct {
	Title       string
	Description string
	Link        string
	Language    string
	Updated     time.Time
}

// Parser wraps gofeed for feed parsing.
type Parser struct {
	parser *gofeed.Parser
}

// NewParser creates a new feed parser.
func NewParser() *Parser {
	return &Parser{
		parser: gofeed.NewParser(),
	}
}

// ParseURL fetches and parses a feed from a URL.
func (p *Parser) ParseURL(ctx context.Context, url string) (*Metadata, []Item, error) {
	// Validate URL for SSRF protection
	if err := ValidateFeedURL(url); err != nil {
		return nil, nil, err
	}

	feed, err := p.parser.ParseURLWithContext(url, ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}

	metadata := &Metadata{
		Title:       feed.Title,
		Description: feed.Description,
		Link:        feed.Link,
		Language:    feed.Language,
	}
	if feed.UpdatedParsed != nil {
		metadata.Updated = *feed.UpdatedParsed
	}

	items := make([]Item, 0, len(feed.Items))
	for _, fi := range feed.Items {
		item := Item{
			ID:          fi.GUID,
			FeedURL:     url,
			Title:       fi.Title,
			Description: fi.Description,
			Link:        fi.Link,
			Content:     fi.Content,
		}

		if fi.Author != nil {
			item.Author = fi.Author.Name
		}
		if fi.PublishedParsed != nil {
			item.Published = *fi.PublishedParsed
		}
		if fi.UpdatedParsed != nil {
			item.Updated = *fi.UpdatedParsed
		}

		// Use link as ID if GUID is empty
		if item.ID == "" {
			item.ID = fi.Link
		}

		items = append(items, item)
	}

	return metadata, items, nil
}

// FetchMetadata fetches only the feed metadata without items.
func (p *Parser) FetchMetadata(ctx context.Context, url string) (*Metadata, error) {
	metadata, _, err := p.ParseURL(ctx, url)
	return metadata, err
}

// Cache provides local caching for feed items using SQLite.
type Cache struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewCache creates a new feed cache.
func NewCache(db *sql.DB) (*Cache, error) {
	cache := &Cache{db: db}
	if err := cache.migrate(); err != nil {
		return nil, fmt.Errorf("migrate cache tables: %w", err)
	}
	return cache, nil
}

func (c *Cache) migrate() error {
	_, err := c.db.Exec(`
		CREATE TABLE IF NOT EXISTS feed_items (
			id TEXT PRIMARY KEY,
			feed_url TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			link TEXT,
			author TEXT,
			published_at DATETIME,
			updated_at DATETIME,
			content TEXT,
			fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_feed_items_feed_url ON feed_items(feed_url);
		CREATE INDEX IF NOT EXISTS idx_feed_items_published_at ON feed_items(published_at DESC);
	`)
	return err
}

// StoreItems stores feed items in the cache.
func (c *Cache) StoreItems(ctx context.Context, items []Item) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO feed_items (id, feed_url, title, description, link, author, published_at, updated_at, content, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`)
	if err != nil {
		return fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()

	for _, item := range items {
		var publishedAt, updatedAt *time.Time
		if !item.Published.IsZero() {
			publishedAt = &item.Published
		}
		if !item.Updated.IsZero() {
			updatedAt = &item.Updated
		}

		_, err := stmt.ExecContext(ctx, item.ID, item.FeedURL, item.Title, item.Description, item.Link, item.Author, publishedAt, updatedAt, item.Content)
		if err != nil {
			return fmt.Errorf("insert item: %w", err)
		}
	}

	return tx.Commit()
}

// GetRecentItemsPaginated retrieves recent items with pagination and optional search.
func (c *Cache) GetRecentItemsPaginated(ctx context.Context, feedURLs []string, search string, limit, offset int) ([]Item, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 {
		limit = 25
	}
	if offset < 0 {
		offset = 0
	}

	if len(feedURLs) == 0 {
		return nil, nil
	}

	// Build query with IN clause
	query := `
		SELECT id, feed_url, title, description, link, author, published_at, updated_at, content
		FROM feed_items
		WHERE feed_url IN (`
	args := make([]interface{}, 0, len(feedURLs)+3)
	for i, url := range feedURLs {
		if i > 0 {
			query += ", "
		}
		query += "?"
		args = append(args, url)
	}
	query += `)`

	// Add search filter if provided
	if search != "" {
		query += ` AND (title LIKE ? OR description LIKE ? OR author LIKE ?)`
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	query += ` ORDER BY COALESCE(published_at, fetched_at) DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query items: %w", err)
	}
	defer rows.Close()

	return scanItems(rows)
}

// CountItems counts total items for pagination.
func (c *Cache) CountItems(ctx context.Context, feedURLs []string, search string) (int, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(feedURLs) == 0 {
		return 0, nil
	}

	query := `SELECT COUNT(*) FROM feed_items WHERE feed_url IN (`
	args := make([]interface{}, 0, len(feedURLs)+3)
	for i, url := range feedURLs {
		if i > 0 {
			query += ", "
		}
		query += "?"
		args = append(args, url)
	}
	query += `)`

	if search != "" {
		query += ` AND (title LIKE ? OR description LIKE ? OR author LIKE ?)`
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	var count int
	err := c.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// CleanupOldItems removes items older than the specified duration.
func (c *Cache) CleanupOldItems(ctx context.Context, olderThan time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	_, err := c.db.ExecContext(ctx, `DELETE FROM feed_items WHERE fetched_at < ?`, cutoff)
	return err
}

func scanItems(rows *sql.Rows) ([]Item, error) {
	var items []Item
	for rows.Next() {
		var item Item
		var publishedAt, updatedAt sql.NullTime
		var description, link, author, content sql.NullString

		err := rows.Scan(&item.ID, &item.FeedURL, &item.Title, &description, &link, &author, &publishedAt, &updatedAt, &content)
		if err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}

		if description.Valid {
			item.Description = description.String
		}
		if link.Valid {
			item.Link = link.String
		}
		if author.Valid {
			item.Author = author.String
		}
		if content.Valid {
			item.Content = content.String
		}
		if publishedAt.Valid {
			item.Published = publishedAt.Time
		}
		if updatedAt.Valid {
			item.Updated = updatedAt.Time
		}

		items = append(items, item)
	}

	return items, rows.Err()
}

// Service coordinates feed operations between local cache.
type Service struct {
	parser *Parser
	cache  *Cache
}

// NewService creates a new feed service.
func NewService(cache *Cache) *Service {
	return &Service{
		parser: NewParser(),
		cache:  cache,
	}
}

// RefreshFeed fetches and caches items from a feed URL.
func (s *Service) RefreshFeed(ctx context.Context, feedURL string) (*Metadata, error) {
	metadata, items, err := s.parser.ParseURL(ctx, feedURL)
	if err != nil {
		return nil, err
	}

	if err := s.cache.StoreItems(ctx, items); err != nil {
		return nil, fmt.Errorf("cache items: %w", err)
	}

	return metadata, nil
}

// GetRecentItemsPaginated retrieves recent items with pagination and search.
func (s *Service) GetRecentItemsPaginated(ctx context.Context, feedURLs []string, search string, limit, offset int) ([]Item, error) {
	return s.cache.GetRecentItemsPaginated(ctx, feedURLs, search, limit, offset)
}

// CountItems counts total items for pagination.
func (s *Service) CountItems(ctx context.Context, feedURLs []string, search string) (int, error) {
	return s.cache.CountItems(ctx, feedURLs, search)
}

// FetchMetadata fetches metadata for a feed URL without caching items.
func (s *Service) FetchMetadata(ctx context.Context, feedURL string) (*Metadata, error) {
	return s.parser.FetchMetadata(ctx, feedURL)
}

// FetchFeed fetches and parses a feed without caching items.
// Returns metadata and items for immediate use.
func (s *Service) FetchFeed(ctx context.Context, feedURL string) (*Metadata, []Item, error) {
	return s.parser.ParseURL(ctx, feedURL)
}

// HTMLMetadata contains metadata extracted from an HTML page.
type HTMLMetadata struct {
	Title       string
	Description string
}

// FetchHTMLMetadata fetches metadata from an HTML page.
func (s *Service) FetchHTMLMetadata(ctx context.Context, url string) (*HTMLMetadata, error) {
	// Validate URL for SSRF protection
	if err := ValidateFeedURL(url); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Feeder/1.0)")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Parse HTML
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse html: %w", err)
	}

	metadata := &HTMLMetadata{}
	extractMetadata(doc, metadata)

	// If no title found, use the URL
	if metadata.Title == "" {
		metadata.Title = url
	}

	return metadata, nil
}

// extractMetadata recursively extracts title and meta tags from HTML
func extractMetadata(n *html.Node, metadata *HTMLMetadata) {
	if n.Type == html.ElementNode {
		if n.Data == "title" && n.FirstChild != nil {
			metadata.Title = strings.TrimSpace(n.FirstChild.Data)
		} else if n.Data == "meta" {
			var name, property, content string
			for _, attr := range n.Attr {
				switch attr.Key {
				case "name":
					name = attr.Val
				case "property":
					property = attr.Val
				case "content":
					content = attr.Val
				}
			}
			// Check for description meta tags
			if (name == "description" || property == "og:description") && metadata.Description == "" {
				metadata.Description = strings.TrimSpace(content)
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		extractMetadata(c, metadata)
	}
}
