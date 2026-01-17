package feed

import "testing"

func TestIsValidItemURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "valid http URL",
			url:      "http://example.com/article",
			expected: true,
		},
		{
			name:     "valid https URL",
			url:      "https://example.com/article",
			expected: true,
		},
		{
			name:     "javascript scheme - blocked",
			url:      "javascript:alert('xss')",
			expected: false,
		},
		{
			name:     "data scheme - blocked",
			url:      "data:text/html,<script>alert('xss')</script>",
			expected: false,
		},
		{
			name:     "file scheme - blocked",
			url:      "file:///etc/passwd",
			expected: false,
		},
		{
			name:     "ftp scheme - blocked",
			url:      "ftp://example.com/file",
			expected: false,
		},
		{
			name:     "empty string - blocked",
			url:      "",
			expected: false,
		},
		{
			name:     "relative URL - blocked",
			url:      "/relative/path",
			expected: false,
		},
		{
			name:     "protocol-relative URL - blocked",
			url:      "//example.com/article",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidItemURL(tt.url)
			if result != tt.expected {
				t.Errorf("IsValidItemURL(%q) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestResolveItemURL(t *testing.T) {
	tests := []struct {
		name        string
		itemURL     string
		feedURL     string
		expected    string
		shouldError bool
	}{
		{
			name:        "absolute http URL - pass through",
			itemURL:     "http://example.com/article",
			feedURL:     "https://feeds.example.com/rss",
			expected:    "http://example.com/article",
			shouldError: false,
		},
		{
			name:        "absolute https URL - pass through",
			itemURL:     "https://example.com/article",
			feedURL:     "https://feeds.example.com/rss",
			expected:    "https://example.com/article",
			shouldError: false,
		},
		{
			name:        "relative path - resolved against feed base",
			itemURL:     "posts/article.html",
			feedURL:     "https://example.com/atom.xml",
			expected:    "https://example.com/posts/article.html",
			shouldError: false,
		},
		{
			name:        "absolute path - resolved against feed base",
			itemURL:     "/posts/article.html",
			feedURL:     "https://example.com/atom.xml",
			expected:    "https://example.com/posts/article.html",
			shouldError: false,
		},
		{
			name:        "real-world case: mrcjkb.dev relative URL",
			itemURL:     "mrcjkb.dev/posts/2023-01-10-luarocks-tag-release.html",
			feedURL:     "https://mrcjkb.dev/atom.xml",
			expected:    "https://mrcjkb.dev/posts/2023-01-10-luarocks-tag-release.html",
			shouldError: false,
		},
		{
			name:        "protocol-relative URL - resolved to https",
			itemURL:     "//cdn.example.com/article",
			feedURL:     "https://example.com/rss",
			expected:    "https://cdn.example.com/article",
			shouldError: false,
		},
		{
			name:        "relative path with query params",
			itemURL:     "article?id=123",
			feedURL:     "https://example.com/feed.xml",
			expected:    "https://example.com/article?id=123",
			shouldError: false,
		},
		{
			name:        "relative path with fragment",
			itemURL:     "posts/article#section",
			feedURL:     "https://example.com/rss",
			expected:    "https://example.com/posts/article#section",
			shouldError: false,
		},
		{
			name:        "javascript scheme - should error",
			itemURL:     "javascript:alert('xss')",
			feedURL:     "https://example.com/rss",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "data scheme - should error",
			itemURL:     "data:text/html,<script>alert('xss')</script>",
			feedURL:     "https://example.com/rss",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "file scheme - should error",
			itemURL:     "file:///etc/passwd",
			feedURL:     "https://example.com/rss",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "ftp scheme - should error",
			itemURL:     "ftp://example.com/file",
			feedURL:     "https://example.com/rss",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "empty item URL - should error",
			itemURL:     "",
			feedURL:     "https://example.com/rss",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "malformed feed URL - should error",
			itemURL:     "posts/article.html",
			feedURL:     "not a url",
			expected:    "",
			shouldError: true,
		},
		{
			name:        "feed URL with subdirectory",
			itemURL:     "article.html",
			feedURL:     "https://example.com/blog/feed.xml",
			expected:    "https://example.com/blog/article.html",
			shouldError: false,
		},
		{
			name:        "relative path going up directory",
			itemURL:     "../posts/article.html",
			feedURL:     "https://example.com/blog/feed.xml",
			expected:    "https://example.com/posts/article.html",
			shouldError: false,
		},
		{
			name:        "URL with international characters",
			itemURL:     "articles/café.html",
			feedURL:     "https://example.com/rss",
			expected:    "https://example.com/articles/caf%C3%A9.html",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ResolveItemURL(tt.itemURL, tt.feedURL)

			if tt.shouldError {
				if err == nil {
					t.Errorf("ResolveItemURL(%q, %q) expected error but got none, result = %q", tt.itemURL, tt.feedURL, result)
				}
			} else {
				if err != nil {
					t.Errorf("ResolveItemURL(%q, %q) unexpected error: %v", tt.itemURL, tt.feedURL, err)
				}
				if result != tt.expected {
					t.Errorf("ResolveItemURL(%q, %q) = %q, want %q", tt.itemURL, tt.feedURL, result, tt.expected)
				}
			}
		})
	}
}

func TestStripHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple HTML",
			input:    "<p>Hello <b>world</b></p>",
			expected: "Hello world",
		},
		{
			name:     "nested tags",
			input:    "<div><span><a href='#'>Link</a></span></div>",
			expected: "Link",
		},
		{
			name:     "with script tag",
			input:    "<p>Text</p><script>alert('xss')</script>",
			expected: "Textalert('xss')",
		},
		{
			name:     "plain text",
			input:    "Just plain text",
			expected: "Just plain text",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "HTML entities",
			input:    "&lt;script&gt;alert('xss')&lt;/script&gt;",
			expected: "<script>alert('xss')</script>",
		},
		{
			name:     "multiple whitespace normalized",
			input:    "<p>Text    with   spaces</p>",
			expected: "Text with spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripHTML(tt.input)
			if result != tt.expected {
				t.Errorf("StripHTML(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
