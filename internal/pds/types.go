// Package pds provides types and client for interacting with AT Protocol PDS.
package pds

import (
	"fmt"
	"strings"
	"time"
)

// Lexicon NSIDs
const (
	FeedNSID            = "solanum.solanaceae.net.feed"
	ReadingItemNSID     = "solanum.solanaceae.net.readingItem"
	LeafletSubscription = "pub.leaflet.graph.subscription"
)

// Feed represents an RSS/Atom feed subscription stored in the user's PDS.
// Corresponds to lexicon: solanum.solanaceae.net.feed
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
// Corresponds to lexicon: solanum.solanaceae.net.readingItem
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
