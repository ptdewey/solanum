// Package public provides embedded static assets and templates.
package public

import "embed"

//go:embed templates/*.tmpl
var TemplatesFS embed.FS

//go:embed static/*
var StaticFS embed.FS
