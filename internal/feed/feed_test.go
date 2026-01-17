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
