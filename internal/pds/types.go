// Package pds provides types and client for interacting with AT Protocol PDS.
package pds

import (
	"fmt"
	"strings"
	"time"
)

// Lexicon NSIDs
const (
	FeedNSID            = "net.solanaceae.solanum.feed"
	ReadingItemNSID     = "net.solanaceae.solanum.readingItem"
	FeedCacheNSID       = "net.solanaceae.solanum.feedCache"
	RemovedEntriesNSID  = "net.solanaceae.solanum.removedEntries"
	LeafletSubscription = "pub.leaflet.graph.subscription"
)

// Feed represents an RSS/Atom feed subscription stored in the user's PDS.
// Corresponds to lexicon: net.solanaceae.solanum.feed
type Feed struct {
	URI         string    `json:"uri,omitempty"`         // AT URI (at://did/collection/rkey)
	CID         string    `json:"cid,omitempty"`         // Content ID
	RKey        string    `json:"rkey,omitempty"`        // Record key
	URL         string    `json:"url"`                   // Feed URL
	Title       string    `json:"title"`                 // Feed title
	Description string    `json:"description,omitempty"` // Feed description
	IsActive    bool      `json:"isActive"`              // Whether feed is active
	CreatedAt   time.Time `json:"createdAt"`             // When feed was added
}

// FeedRecord is the record format for PDS storage.
type FeedRecord struct {
	Type        string `json:"$type"`
	URL         string `json:"url"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	IsActive    bool   `json:"isActive"`
	CreatedAt   string `json:"createdAt"`
}

// ToRecord converts a Feed to its PDS record format.
func (f *Feed) ToRecord() FeedRecord {
	return FeedRecord{
		Type:        FeedNSID,
		URL:         f.URL,
		Title:       f.Title,
		Description: f.Description,
		IsActive:    f.IsActive,
		CreatedAt:   f.CreatedAt.Format(time.RFC3339),
	}
}

// ReadingItem represents a reading list bookmark stored in the user's PDS.
// Corresponds to lexicon: net.solanaceae.solanum.readingItem
type ReadingItem struct {
	URI         string     `json:"uri,omitempty"`         // AT URI
	CID         string     `json:"cid,omitempty"`         // Content ID
	RKey        string     `json:"rkey,omitempty"`        // Record key
	URL         string     `json:"url"`                   // Article URL
	Title       string     `json:"title"`                 // Article title
	Description string     `json:"description,omitempty"` // Description/excerpt
	IsArchived  bool       `json:"isArchived"`            // Whether item is read
	ArchivedAt  *time.Time `json:"archivedAt,omitempty"`  // When archived
	CreatedAt   time.Time  `json:"createdAt"`             // When added
}

// ReadingItemRecord is the record format for PDS storage.
type ReadingItemRecord struct {
	Type        string `json:"$type"`
	URL         string `json:"url"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	IsArchived  bool   `json:"isArchived"`
	ArchivedAt  string `json:"archivedAt,omitempty"`
	CreatedAt   string `json:"createdAt"`
}

// ToRecord converts a ReadingItem to its PDS record format.
func (r *ReadingItem) ToRecord() ReadingItemRecord {
	rec := ReadingItemRecord{
		Type:        ReadingItemNSID,
		URL:         r.URL,
		Title:       r.Title,
		Description: r.Description,
		IsArchived:  r.IsArchived,
		CreatedAt:   r.CreatedAt.Format(time.RFC3339),
	}
	if r.ArchivedAt != nil {
		rec.ArchivedAt = r.ArchivedAt.Format(time.RFC3339)
	}
	return rec
}

// LeafletSubscription represents a pub.leaflet.graph.subscription record.
// This is used to read existing RSS subscriptions from Leaflet.
type LeafletSubscriptionRecord struct {
	URI         string    `json:"uri,omitempty"`       // AT URI of the subscription record
	CID         string    `json:"cid,omitempty"`       // Content ID
	RKey        string    `json:"rkey,omitempty"`      // Record key
	Type        string    `json:"$type"`               // Should be "pub.leaflet.graph.subscription"
	Publication string    `json:"publication"`         // AT URI pointing to a Leaflet publication (at://did/pub.leaflet.publication/rkey)
	Title       string    `json:"title,omitempty"`     // Feed title
	CreatedAt   time.Time `json:"createdAt,omitempty"` // When subscribed
}

// LeafletPublication represents a pub.leaflet.publication record.
// This contains the actual publication URL and RSS feed information.
type LeafletPublication struct {
	Type     string `json:"$type"`     // Should be "pub.leaflet.publication"
	BasePath string `json:"base_path"` // The publication base URL (e.g., "https://marvins-guide.leaflet.pub")
	Title    string `json:"title,omitempty"`
}

// ExtractDIDAndRKey extracts the DID and record key from the Publication URI.
func (l *LeafletSubscriptionRecord) ExtractDIDAndRKey() (did, rkey string, err error) {
	// Publication format: at://did:plc:xxx/pub.leaflet.publication/rkey
	if l.Publication == "" {
		return "", "", fmt.Errorf("publication is empty")
	}

	// Parse AT URI: at://did/collection/rkey
	parts := strings.Split(strings.TrimPrefix(l.Publication, "at://"), "/")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid AT URI format: %s", l.Publication)
	}

	return parts[0], parts[2], nil
}

// BlobRef represents a reference to an uploaded blob.
type BlobRef struct {
	Type     string  `json:"$type"`
	Ref      CIDLink `json:"ref"`
	MimeType string  `json:"mimeType"`
	Size     int     `json:"size"`
}

// CIDLink represents a CID reference.
type CIDLink struct {
	Link string `json:"$link"`
}

// FeedCache represents cached feed items stored as a blob.
// Corresponds to lexicon: net.solanaceae.solanum.feedCache
type FeedCache struct {
	URI         string    `json:"uri,omitempty"`  // AT URI
	CID         string    `json:"cid,omitempty"`  // Content ID
	RKey        string    `json:"rkey,omitempty"` // Record key (always "self")
	Blob        BlobRef   `json:"blob"`           // Blob reference
	LastUpdated time.Time `json:"lastUpdated"`    // When cache was last refreshed
	ItemCount   int       `json:"itemCount"`      // Number of items in cache
	FeedCount   int       `json:"feedCount"`      // Number of feeds in cache
}

// FeedCacheRecord is the record format for PDS storage.
type FeedCacheRecord struct {
	Type        string  `json:"$type"`
	Blob        BlobRef `json:"blob"`
	LastUpdated string  `json:"lastUpdated"`
	ItemCount   int     `json:"itemCount"`
	FeedCount   int     `json:"feedCount"`
}

// ToRecord converts a FeedCache to its PDS record format.
func (fc *FeedCache) ToRecord() FeedCacheRecord {
	return FeedCacheRecord{
		Type:        FeedCacheNSID,
		Blob:        fc.Blob,
		LastUpdated: fc.LastUpdated.Format(time.RFC3339),
		ItemCount:   fc.ItemCount,
		FeedCount:   fc.FeedCount,
	}
}

// FeedCacheData is the JSON structure stored in the blob.
type FeedCacheData struct {
	LastUpdated time.Time       `json:"lastUpdated"`
	Items       []FeedCacheItem `json:"items"`
}

// FeedCacheItem represents a cached feed item in the blob.
type FeedCacheItem struct {
	ID          string    `json:"id"`
	FeedURL     string    `json:"feedURL"`
	FeedTitle   string    `json:"feedTitle"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Link        string    `json:"link"`
	Author      string    `json:"author,omitempty"`
	Published   time.Time `json:"published"`
	Content     string    `json:"content,omitempty"`
}

// RemovedEntries represents the list of removed feed entries stored as a blob.
// Corresponds to lexicon: net.solanaceae.solanum.removedEntries
type RemovedEntries struct {
	URI         string    `json:"uri,omitempty"`  // AT URI
	CID         string    `json:"cid,omitempty"`  // Content ID
	RKey        string    `json:"rkey,omitempty"` // Record key (always "self")
	Blob        BlobRef   `json:"blob"`           // Blob reference
	LastUpdated time.Time `json:"lastUpdated"`    // When list was last updated
	EntryCount  int       `json:"entryCount"`     // Number of removed entries
}

// RemovedEntriesRecord is the record format for PDS storage.
type RemovedEntriesRecord struct {
	Type        string  `json:"$type"`
	Blob        BlobRef `json:"blob"`
	LastUpdated string  `json:"lastUpdated"`
	EntryCount  int     `json:"entryCount"`
}

// ToRecord converts RemovedEntries to its PDS record format.
func (re *RemovedEntries) ToRecord() RemovedEntriesRecord {
	return RemovedEntriesRecord{
		Type:        RemovedEntriesNSID,
		Blob:        re.Blob,
		LastUpdated: re.LastUpdated.Format(time.RFC3339),
		EntryCount:  re.EntryCount,
	}
}

// RemovedEntriesData is the JSON structure stored in the blob.
type RemovedEntriesData struct {
	LastUpdated time.Time `json:"lastUpdated"`
	URLs        []string  `json:"urls"` // List of removed entry URLs
}
