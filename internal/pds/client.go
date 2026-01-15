// Package pds provides a client for interacting with AT Protocol PDS.
package pds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

const slingshotBaseURL = "https://slingshot.microcosm.blue"

// MaxBlobSize is the maximum size of a blob in bytes (1MB).
// AT Protocol spec allows up to 1MB blobs.
const MaxBlobSize = 1024 * 1024

// Client provides methods for reading and writing records to a user's PDS.
type Client struct {
	api *atclient.APIClient
	did syntax.DID
}

// NewClient creates a new PDS client for the given user.
func NewClient(apiClient *atclient.APIClient, did syntax.DID) *Client {
	return &Client{
		api: apiClient,
		did: did,
	}
}

// ListFeeds retrieves all feed subscriptions from the user's PDS.
func (c *Client) ListFeeds(ctx context.Context) ([]Feed, error) {
	records, err := c.listRecords(ctx, FeedNSID)
	if err != nil {
		return nil, err
	}

	feeds := make([]Feed, 0, len(records))
	for _, rec := range records {
		var feed Feed
		if err := json.Unmarshal(rec.Value, &feed); err != nil {
			continue // Skip invalid records
		}
		feed.URI = rec.URI
		feed.CID = rec.CID
		feed.RKey = extractRKey(rec.URI)
		feeds = append(feeds, feed)
	}
	return feeds, nil
}

// GetFeed retrieves a single feed by its record key.
func (c *Client) GetFeed(ctx context.Context, rkey string) (*Feed, error) {
	rec, err := c.getRecord(ctx, FeedNSID, rkey)
	if err != nil {
		return nil, err
	}

	var feed Feed
	if err := json.Unmarshal(rec.Value, &feed); err != nil {
		return nil, fmt.Errorf("unmarshal feed: %w", err)
	}
	feed.URI = rec.URI
	feed.CID = rec.CID
	feed.RKey = rkey
	return &feed, nil
}

// CreateFeed creates a new feed subscription in the user's PDS.
func (c *Client) CreateFeed(ctx context.Context, feed *Feed) (string, string, error) {
	feed.CreatedAt = time.Now().UTC()
	if !feed.IsActive {
		feed.IsActive = true // Default to active
	}
	return c.createRecord(ctx, FeedNSID, feed.ToRecord())
}

// UpdateFeed updates an existing feed subscription.
func (c *Client) UpdateFeed(ctx context.Context, rkey string, feed *Feed) (string, error) {
	return c.putRecord(ctx, FeedNSID, rkey, feed.ToRecord())
}

// DeleteFeed removes a feed subscription from the user's PDS.
func (c *Client) DeleteFeed(ctx context.Context, rkey string) error {
	return c.deleteRecord(ctx, FeedNSID, rkey)
}

// ListReadingItems retrieves all reading list items from the user's PDS.
func (c *Client) ListReadingItems(ctx context.Context) ([]ReadingItem, error) {
	records, err := c.listRecords(ctx, ReadingItemNSID)
	if err != nil {
		return nil, err
	}

	items := make([]ReadingItem, 0, len(records))
	for _, rec := range records {
		var item ReadingItem
		if err := json.Unmarshal(rec.Value, &item); err != nil {
			continue // Skip invalid records
		}
		item.URI = rec.URI
		item.CID = rec.CID
		item.RKey = extractRKey(rec.URI)
		items = append(items, item)
	}
	return items, nil
}

// GetReadingItem retrieves a single reading item by its record key.
func (c *Client) GetReadingItem(ctx context.Context, rkey string) (*ReadingItem, error) {
	rec, err := c.getRecord(ctx, ReadingItemNSID, rkey)
	if err != nil {
		return nil, err
	}

	var item ReadingItem
	if err := json.Unmarshal(rec.Value, &item); err != nil {
		return nil, fmt.Errorf("unmarshal reading item: %w", err)
	}
	item.URI = rec.URI
	item.CID = rec.CID
	item.RKey = rkey
	return &item, nil
}

// CreateReadingItem creates a new reading list item in the user's PDS.
func (c *Client) CreateReadingItem(ctx context.Context, item *ReadingItem) (string, string, error) {
	item.CreatedAt = time.Now().UTC()
	return c.createRecord(ctx, ReadingItemNSID, item.ToRecord())
}

// UpdateReadingItem updates an existing reading list item.
func (c *Client) UpdateReadingItem(ctx context.Context, rkey string, item *ReadingItem) (string, error) {
	return c.putRecord(ctx, ReadingItemNSID, rkey, item.ToRecord())
}

// ArchiveReadingItem marks a reading item as archived (read).
func (c *Client) ArchiveReadingItem(ctx context.Context, rkey string) error {
	item, err := c.GetReadingItem(ctx, rkey)
	if err != nil {
		return fmt.Errorf("get reading item: %w", err)
	}
	now := time.Now().UTC()
	item.IsArchived = true
	item.ArchivedAt = &now
	_, err = c.UpdateReadingItem(ctx, rkey, item)
	return err
}

// DeleteReadingItem removes a reading list item from the user's PDS.
func (c *Client) DeleteReadingItem(ctx context.Context, rkey string) error {
	return c.deleteRecord(ctx, ReadingItemNSID, rkey)
}

// ListLeafletSubscriptions retrieves all Leaflet RSS subscriptions from the user's PDS.
// These can be used to prepopulate feeds.
func (c *Client) ListLeafletSubscriptions(ctx context.Context) ([]LeafletSubscriptionRecord, error) {
	records, err := c.listRecords(ctx, LeafletSubscription)
	if err != nil {
		// If Leaflet collection doesn't exist, return empty list
		return []LeafletSubscriptionRecord{}, nil
	}

	subs := make([]LeafletSubscriptionRecord, 0, len(records))
	for _, rec := range records {
		var sub LeafletSubscriptionRecord
		if err := json.Unmarshal(rec.Value, &sub); err != nil {
			continue // Skip invalid records
		}
		sub.URI = rec.URI
		sub.CID = rec.CID
		sub.RKey = extractRKey(rec.URI)
		subs = append(subs, sub)
	}
	return subs, nil
}

// GetLeafletFeedRSSURL fetches the Leaflet publication record via Slingshot and returns the RSS URL.
// Slingshot is a fast edge cache for atproto records that handles DID resolution automatically.
func (c *Client) GetLeafletFeedRSSURL(ctx context.Context, publicationURI string) (string, error) {
	// Parse the AT URI to extract DID, collection, and rkey
	parts := strings.Split(strings.TrimPrefix(publicationURI, "at://"), "/")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid AT URI format: %s", publicationURI)
	}

	repo := parts[0]
	collection := parts[1]
	rkey := parts[2]

	// Use Slingshot to fetch the record (handles DID resolution internally)
	reqURL := fmt.Sprintf("%s/xrpc/com.atproto.repo.getRecord?repo=%s&collection=%s&rkey=%s",
		slingshotBaseURL,
		url.QueryEscape(repo),
		url.QueryEscape(collection),
		url.QueryEscape(rkey))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch from slingshot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("slingshot returned HTTP %d", resp.StatusCode)
	}

	var result getRecordResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	var publication LeafletPublication
	if err := json.Unmarshal(result.Value, &publication); err != nil {
		return "", fmt.Errorf("unmarshal publication: %w", err)
	}

	if publication.BasePath == "" {
		return "", fmt.Errorf("publication has no base_path")
	}

	// BasePath doesn't include https://, so we need to add it
	basePath := publication.BasePath
	if !strings.HasPrefix(basePath, "http") {
		basePath = "https://" + basePath
	}

	return basePath + "/rss", nil
}

// UploadBlob uploads binary data as a blob to the PDS with the specified MIME type.
// Returns the blob reference needed for embedding in records.
//
// TODO: atproto.RepoUploadBlob exists but doesn't support setting Content-Type header.
// If indigo adds Content-Type support, switch to using that simpler function instead.
func (c *Client) UploadBlob(ctx context.Context, data []byte, mimeType string) (*BlobRef, error) {
	// Validate blob size
	if len(data) > MaxBlobSize {
		return nil, fmt.Errorf("blob size %d exceeds maximum allowed size %d bytes", len(data), MaxBlobSize)
	}

	// Create a reader for the data
	reader := bytes.NewReader(data)

	// Create the API request with Content-Type header
	endpoint, err := syntax.ParseNSID("com.atproto.repo.uploadBlob")
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}

	req := atclient.NewAPIRequest(http.MethodPost, endpoint, reader)
	req.Headers = http.Header{}
	req.Headers.Set("Content-Type", mimeType)
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}

	// Make the request
	resp, err := c.api.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("upload blob: %w", err)
	}
	defer resp.Body.Close()

	// Parse the response
	var output atproto.RepoUploadBlob_Output
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if output.Blob == nil {
		return nil, fmt.Errorf("upload succeeded but returned nil blob")
	}

	// Convert LexBlob to our BlobRef format
	blobRef := &BlobRef{
		Type:     "blob",
		MimeType: output.Blob.MimeType,
		Size:     int(output.Blob.Size),
		Ref: CIDLink{
			Link: output.Blob.Ref.String(),
		},
	}

	return blobRef, nil
}

// GetBlob retrieves a blob from the PDS using indigo's native function.
// Returns the blob data and its MIME type.
func (c *Client) GetBlob(ctx context.Context, cid string) ([]byte, string, error) {
	// Use indigo's native SyncGetBlob function
	data, err := atproto.SyncGetBlob(ctx, c.api, cid, c.did.String())
	if err != nil {
		return nil, "", fmt.Errorf("sync get blob: %w", err)
	}

	// Check if we got a file stream object instead of actual data (PDS bug)
	if isFileStreamObject(data) {
		return nil, "", fmt.Errorf("PDS returned file stream object instead of blob data. This is a bug in the official Bluesky PDS. CID: %s. The blob was likely uploaded with an incompatible method. Try refreshing the feed cache to re-upload", cid)
	}

	// Default mime type (indigo doesn't return it from SyncGetBlob)
	mimeType := "application/octet-stream"
	if len(data) > 0 && data[0] == '{' {
		mimeType = "application/json"
	}

	return data, mimeType, nil
}

// isFileStreamObject checks if the data is a JSON-serialized Node.js ReadStream object
func isFileStreamObject(data []byte) bool {
	if len(data) == 0 || data[0] != '{' {
		return false
	}

	var streamObj map[string]interface{}
	if err := json.Unmarshal(data, &streamObj); err != nil {
		return false
	}

	// Check if this looks like a ReadStream object
	_, hasPath := streamObj["path"]
	_, hasReadableState := streamObj["_readableState"]
	return hasPath && hasReadableState
}

// GetFeedCache retrieves the feed cache record.
func (c *Client) GetFeedCache(ctx context.Context) (*FeedCache, error) {
	rec, err := c.getRecord(ctx, FeedCacheNSID, "self")
	if err != nil {
		return nil, err
	}

	var cache FeedCache
	if err := json.Unmarshal(rec.Value, &cache); err != nil {
		return nil, fmt.Errorf("unmarshal feed cache: %w", err)
	}
	cache.URI = rec.URI
	cache.CID = rec.CID
	cache.RKey = "self"
	return &cache, nil
}

// CreateFeedCache creates or updates the feed cache record.
// Uses putRecord to upsert with the literal "self" rkey.
func (c *Client) CreateFeedCache(ctx context.Context, cache *FeedCache) (string, error) {
	cache.LastUpdated = time.Now().UTC()
	return c.putRecord(ctx, FeedCacheNSID, "self", cache.ToRecord())
}

// UpdateFeedCache updates the feed cache record.
func (c *Client) UpdateFeedCache(ctx context.Context, cache *FeedCache) (string, error) {
	cache.LastUpdated = time.Now().UTC()
	return c.putRecord(ctx, FeedCacheNSID, "self", cache.ToRecord())
}

// DeleteFeedCache removes the feed cache record.
func (c *Client) DeleteFeedCache(ctx context.Context) error {
	return c.deleteRecord(ctx, FeedCacheNSID, "self")
}

// GetRemovedEntries retrieves the removed entries record.
func (c *Client) GetRemovedEntries(ctx context.Context) (*RemovedEntries, error) {
	rec, err := c.getRecord(ctx, RemovedEntriesNSID, "self")
	if err != nil {
		return nil, err
	}

	var removed RemovedEntries
	if err := json.Unmarshal(rec.Value, &removed); err != nil {
		return nil, fmt.Errorf("unmarshal removed entries: %w", err)
	}
	removed.URI = rec.URI
	removed.CID = rec.CID
	removed.RKey = "self"
	return &removed, nil
}

// CreateRemovedEntries creates or updates the removed entries record.
// Uses putRecord to upsert with the literal "self" rkey.
func (c *Client) CreateRemovedEntries(ctx context.Context, removed *RemovedEntries) (string, error) {
	removed.LastUpdated = time.Now().UTC()
	return c.putRecord(ctx, RemovedEntriesNSID, "self", removed.ToRecord())
}

// UpdateRemovedEntries updates the removed entries record.
func (c *Client) UpdateRemovedEntries(ctx context.Context, removed *RemovedEntries) (string, error) {
	removed.LastUpdated = time.Now().UTC()
	return c.putRecord(ctx, RemovedEntriesNSID, "self", removed.ToRecord())
}

// DeleteRemovedEntries removes the removed entries record.
func (c *Client) DeleteRemovedEntries(ctx context.Context) error {
	return c.deleteRecord(ctx, RemovedEntriesNSID, "self")
}

// AddRemovedEntry adds a URL to the removed entries list.
func (c *Client) AddRemovedEntry(ctx context.Context, url string) error {
	// Try to get existing removed entries
	removed, err := c.GetRemovedEntries(ctx)
	if err != nil {
		// If doesn't exist, create new one with empty blob
		removedData := RemovedEntriesData{
			LastUpdated: time.Now().UTC(),
			URLs:        []string{url},
		}

		jsonData, err := json.Marshal(removedData)
		if err != nil {
			return fmt.Errorf("marshal removed entries data: %w", err)
		}

		blobRef, err := c.UploadBlob(ctx, jsonData, "text/plain")
		if err != nil {
			return fmt.Errorf("upload blob: %w", err)
		}

		removed = &RemovedEntries{
			Blob:        *blobRef,
			LastUpdated: time.Now().UTC(),
			EntryCount:  1,
		}

		_, err = c.CreateRemovedEntries(ctx, removed)
		return err
	}

	// Download existing blob
	blobData, _, err := c.GetBlob(ctx, removed.Blob.Ref.Link)
	if err != nil {
		return fmt.Errorf("get blob: %w", err)
	}

	// Parse existing data
	var removedData RemovedEntriesData
	if err := json.Unmarshal(blobData, &removedData); err != nil {
		return fmt.Errorf("unmarshal removed entries data: %w", err)
	}

	// Check if URL already exists
	for _, existingURL := range removedData.URLs {
		if existingURL == url {
			return nil // Already removed
		}
	}

	// Add new URL
	removedData.URLs = append(removedData.URLs, url)
	removedData.LastUpdated = time.Now().UTC()

	// Upload updated blob
	jsonData, err := json.Marshal(removedData)
	if err != nil {
		return fmt.Errorf("marshal removed entries data: %w", err)
	}

	blobRef, err := c.UploadBlob(ctx, jsonData, "text/plain")
	if err != nil {
		return fmt.Errorf("upload blob: %w", err)
	}

	// Update record
	removed.Blob = *blobRef
	removed.EntryCount = len(removedData.URLs)
	_, err = c.UpdateRemovedEntries(ctx, removed)
	return err
}

// GetRemovedURLs retrieves the list of removed URLs from the blob.
func (c *Client) GetRemovedURLs(ctx context.Context) ([]string, error) {
	removed, err := c.GetRemovedEntries(ctx)
	if err != nil {
		// If record doesn't exist, return empty list
		return []string{}, nil
	}

	// Download blob
	blobData, _, err := c.GetBlob(ctx, removed.Blob.Ref.Link)
	if err != nil {
		return nil, fmt.Errorf("get blob: %w", err)
	}

	// Parse data
	var removedData RemovedEntriesData
	if err := json.Unmarshal(blobData, &removedData); err != nil {
		return nil, fmt.Errorf("unmarshal removed entries data: %w", err)
	}

	return removedData.URLs, nil
}

// Record represents a generic PDS record response.
type record struct {
	URI   string          `json:"uri"`
	CID   string          `json:"cid"`
	Value json.RawMessage `json:"value"`
}

// listRecordsResponse is the response from com.atproto.repo.listRecords.
type listRecordsResponse struct {
	Records []record `json:"records"`
	Cursor  string   `json:"cursor"`
}

// getRecordResponse is the response from com.atproto.repo.getRecord.
type getRecordResponse struct {
	URI   string          `json:"uri"`
	CID   string          `json:"cid"`
	Value json.RawMessage `json:"value"`
}

// createRecordResponse is the response from com.atproto.repo.createRecord.
type createRecordResponse struct {
	URI string `json:"uri"`
	CID string `json:"cid"`
}

// putRecordResponse is the response from com.atproto.repo.putRecord.
type putRecordResponse struct {
	URI string `json:"uri"`
	CID string `json:"cid"`
}

func (c *Client) listRecords(ctx context.Context, collection string) ([]record, error) {
	var cursor string
	var results []record

	for {
		params := map[string]any{
			"repo":       c.did.String(),
			"collection": collection,
			"limit":      100,
		}
		if cursor != "" {
			params["cursor"] = cursor
		}

		var resp listRecordsResponse
		nsid := syntax.NSID("com.atproto.repo.listRecords")
		if err := c.api.Get(ctx, nsid, params, &resp); err != nil {
			return nil, fmt.Errorf("list records: %w", err)
		}

		results = append(results, resp.Records...)

		if resp.Cursor == "" {
			break
		}
		cursor = resp.Cursor
	}

	return results, nil
}

func (c *Client) getRecord(ctx context.Context, collection, rkey string) (*record, error) {
	params := map[string]any{
		"repo":       c.did.String(),
		"collection": collection,
		"rkey":       rkey,
	}

	var resp getRecordResponse
	nsid := syntax.NSID("com.atproto.repo.getRecord")
	if err := c.api.Get(ctx, nsid, params, &resp); err != nil {
		return nil, fmt.Errorf("get record: %w", err)
	}

	return &record{
		URI:   resp.URI,
		CID:   resp.CID,
		Value: resp.Value,
	}, nil
}

func (c *Client) createRecord(ctx context.Context, collection string, rec any) (uri string, cid string, err error) {
	body := map[string]any{
		"repo":       c.did.String(),
		"collection": collection,
		"record":     rec,
	}

	var resp createRecordResponse
	nsid := syntax.NSID("com.atproto.repo.createRecord")
	if err := c.api.Post(ctx, nsid, body, &resp); err != nil {
		return "", "", fmt.Errorf("create record: %w", err)
	}

	return resp.URI, resp.CID, nil
}

func (c *Client) putRecord(ctx context.Context, collection, rkey string, rec any) (cid string, err error) {
	body := map[string]any{
		"repo":       c.did.String(),
		"collection": collection,
		"rkey":       rkey,
		"record":     rec,
	}

	var resp putRecordResponse
	nsid := syntax.NSID("com.atproto.repo.putRecord")
	if err := c.api.Post(ctx, nsid, body, &resp); err != nil {
		return "", fmt.Errorf("put record: %w", err)
	}

	return resp.CID, nil
}

func (c *Client) deleteRecord(ctx context.Context, collection, rkey string) error {
	body := map[string]any{
		"repo":       c.did.String(),
		"collection": collection,
		"rkey":       rkey,
	}

	nsid := syntax.NSID("com.atproto.repo.deleteRecord")
	if err := c.api.Post(ctx, nsid, body, nil); err != nil {
		return fmt.Errorf("delete record: %w", err)
	}

	return nil
}

// extractRKey extracts the record key from an AT URI.
// AT URIs have the format: at://did/collection/rkey
func extractRKey(uri string) string {
	parts := strings.Split(uri, "/")
	if len(parts) >= 5 {
		return parts[len(parts)-1]
	}
	return ""
}
