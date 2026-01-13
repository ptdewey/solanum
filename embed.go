// Package solanum provides embedded static assets and templates for the main application.
package main

import "embed"

//go:embed templates/*.tmpl
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS
