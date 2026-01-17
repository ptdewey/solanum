// Package feed provides RSS/Atom feed parsing.
package feed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
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
		// Resolve item link against feed URL to handle relative URLs
		resolvedLink, err := ResolveItemURL(fi.Link, url)
		if err != nil {
			// Skip items with invalid URLs and log the issue
			// This includes malformed URLs and dangerous schemes
			continue
		}

		// Resolve ID/GUID if it looks like a URL
		itemID := fi.GUID
		if itemID == "" || strings.Contains(itemID, "/") || strings.Contains(itemID, ".") {
			// Try to resolve GUID as URL if it appears to be one
			if itemID == "" {
				itemID = resolvedLink // Use resolved link as fallback
			} else if resolvedID, err := ResolveItemURL(itemID, url); err == nil {
				itemID = resolvedID
			}
			// If resolution fails, keep original GUID
		}

		item := Item{
			ID:          itemID,
			FeedURL:     url,
			Title:       fi.Title,
			Description: StripHTML(fi.Description),
			Link:        resolvedLink, // Use resolved URL
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

		items = append(items, item)
	}

	return metadata, items, nil
}

// FetchMetadata fetches only the feed metadata without items.
func (p *Parser) FetchMetadata(ctx context.Context, url string) (*Metadata, error) {
	metadata, _, err := p.ParseURL(ctx, url)
	return metadata, err
}

// Service coordinates feed operations.
type Service struct {
	parser *Parser
}

// NewService creates a new feed service.
func NewService() *Service {
	return &Service{
		parser: NewParser(),
	}
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

// StripHTML removes HTML tags from a string and returns plain text.
// It properly handles HTML entities and nested tags.
func StripHTML(s string) string {
	if s == "" {
		return ""
	}

	// Parse the HTML
	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		// If parsing fails, just return the original string
		// (it might not be HTML)
		return strings.TrimSpace(s)
	}

	// Extract text content
	var buf strings.Builder
	var extractText func(*html.Node)
	extractText = func(n *html.Node) {
		if n.Type == html.TextNode {
			buf.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractText(c)
		}
	}
	extractText(doc)

	// Normalize whitespace
	text := buf.String()
	text = strings.Join(strings.Fields(text), " ")

	return strings.TrimSpace(text)
}

// IsValidItemURL checks if a URL is a valid http or https URL.
// This prevents javascript:, data:, and other dangerous URL schemes from being stored.
func IsValidItemURL(itemURL string) bool {
	if itemURL == "" {
		return false
	}
	return strings.HasPrefix(itemURL, "http://") || strings.HasPrefix(itemURL, "https://")
}

// ResolveItemURL resolves a potentially relative item URL against the feed's base URL.
// It handles:
// - Absolute URLs (returned as-is if valid)
// - Protocol-relative URLs (inherits scheme from base)
// - Absolute paths (uses base's host)
// - Relative paths (resolves against base)
//
// Returns an error if:
// - Either URL cannot be parsed
// - The resolved URL has a dangerous scheme (not http/https)
func ResolveItemURL(itemURL, feedURL string) (string, error) {
	if itemURL == "" {
		return "", fmt.Errorf("item URL is empty")
	}

	// Parse feed URL as base
	base, err := url.Parse(feedURL)
	if err != nil {
		return "", fmt.Errorf("invalid feed URL: %w", err)
	}

	// Parse item URL
	ref, err := url.Parse(itemURL)
	if err != nil {
		return "", fmt.Errorf("invalid item URL: %w", err)
	}

	// Check if this looks like an absolute URL without a scheme
	// (e.g., "example.com/path" or "//example.com/path")
	// If the parsed URL has a hostname but no scheme, it's likely missing the scheme
	if ref.Scheme == "" && ref.Host == "" && strings.Contains(itemURL, "/") {
		// Try to detect if this is a domain-like path (contains a dot before the first slash)
		// But exclude relative paths like "../path" or "./path"
		if !strings.HasPrefix(itemURL, ".") && !strings.HasPrefix(itemURL, "/") {
			firstSlash := strings.Index(itemURL, "/")
			beforeSlash := itemURL[:firstSlash]
			if strings.Contains(beforeSlash, ".") {
				// This looks like "domain.com/path" - treat as absolute URL with missing scheme
				itemURL = "https://" + itemURL
				ref, err = url.Parse(itemURL)
				if err != nil {
					return "", fmt.Errorf("invalid item URL: %w", err)
				}
			}
		}
	}

	// Resolve relative URL against base
	resolved := base.ResolveReference(ref)

	// Validate the resolved URL has a safe scheme
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("resolved URL has invalid scheme '%s' (only http/https allowed)", resolved.Scheme)
	}

	return resolved.String(), nil
}
