// Package purl parses package URLs (https://github.com/package-url/purl-spec)
// and maps them to the interned software key (software_versions:
// ecosystem, distro, release, name, version, arch, source). Container image
// SBOMs (registry attestations, Syft) identify every package by its purl,
// so this is how image packages join host packages and the matcher
// (DOMAIN_MODEL.md §2.2, docs/decisions/container-image-vulnerabilities.md).
//
// The parser is our own (about a page of code, following the spec's
// "How to parse" section) rather than packageurl-go: we only read purls,
// the mapping below applies its own per-type normalisation anyway, and it
// avoids a dependency until server-side Syft (which brings packageurl-go
// with it) lands.
package purl

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// PURL is a parsed package URL. Every component is percent-decoded.
// Type is lowercased; Namespace and Name are as written (type-specific
// normalisation is the mapping's job, see Map).
type PURL struct {
	Type       string
	Namespace  string // '/'-joined segments, "" when none
	Name       string
	Version    string
	Qualifiers map[string]string // keys lowercased; empty values dropped
	Subpath    string
}

// Parse parses s as a package URL:
//
//	pkg:type/namespace/name@version?qualifiers#subpath
//
// Only type and name are required. It is lenient where real SBOMs are
// (a "pkg://" prefix, upper-case type) and strict where a wrong result
// would be silent (bad percent-encoding, missing name).
func Parse(s string) (PURL, error) {
	var p PURL
	rest, ok := cutPrefixFold(s, "pkg:")
	if !ok {
		return p, fmt.Errorf("purl %q: scheme is not pkg", s)
	}
	rest = strings.TrimLeft(rest, "/")

	if i := strings.LastIndexByte(rest, '#'); i >= 0 {
		sub, err := decodeSegments(rest[i+1:])
		if err != nil {
			return p, fmt.Errorf("purl %q: subpath: %w", s, err)
		}
		p.Subpath, rest = sub, rest[:i]
	}
	if i := strings.LastIndexByte(rest, '?'); i >= 0 {
		q, err := parseQualifiers(rest[i+1:])
		if err != nil {
			return p, fmt.Errorf("purl %q: %w", s, err)
		}
		p.Qualifiers, rest = q, rest[:i]
	}
	// The version separator is the last '@' after the last '/': an npm
	// scope written unencoded ("@babel/core") must not be taken for it.
	slash := strings.LastIndexByte(rest, '/')
	if i := strings.LastIndexByte(rest, '@'); i > slash {
		v, err := url.PathUnescape(rest[i+1:])
		if err != nil {
			return p, fmt.Errorf("purl %q: version: %w", s, err)
		}
		p.Version, rest = v, rest[:i]
	}

	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" {
		return p, fmt.Errorf("purl %q: missing type or name", s)
	}
	p.Type = strings.ToLower(typ)
	path = strings.Trim(path, "/")
	var err error
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		if p.Namespace, err = decodeSegments(path[:i]); err != nil {
			return p, fmt.Errorf("purl %q: namespace: %w", s, err)
		}
		path = path[i+1:]
	}
	if p.Name, err = url.PathUnescape(path); err != nil {
		return p, fmt.Errorf("purl %q: name: %w", s, err)
	}
	if p.Name == "" {
		return p, fmt.Errorf("purl %q: missing name", s)
	}
	return p, nil
}

// Qualifier returns the named qualifier ("" when absent).
func (p PURL) Qualifier(key string) string { return p.Qualifiers[key] }

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// decodeSegments percent-decodes each '/'-separated segment, dropping
// empty ones, and rejoins them with '/'.
func decodeSegments(s string) (string, error) {
	var out []string
	for seg := range strings.SplitSeq(s, "/") {
		if seg == "" {
			continue
		}
		d, err := url.PathUnescape(seg)
		if err != nil {
			return "", err
		}
		out = append(out, d)
	}
	return strings.Join(out, "/"), nil
}

var errEmptyQualifierKey = errors.New("empty qualifier key")

// parseQualifiers parses "k=v&k2=v2". Values are percent-decoded ('+' is
// a literal plus, as in Debian versions, not a space); keys are
// lowercased; empty values are dropped, as the spec says.
func parseQualifiers(s string) (map[string]string, error) {
	q := map[string]string{}
	for pair := range strings.SplitSeq(s, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if k == "" {
			return nil, errEmptyQualifierKey
		}
		d, err := url.PathUnescape(v)
		if err != nil {
			return nil, fmt.Errorf("qualifier %s: %w", k, err)
		}
		if d != "" {
			q[strings.ToLower(k)] = d
		}
	}
	return q, nil
}
