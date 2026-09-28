package sbom

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pippinmole/upkeep.sh/server/internal/purl"
)

// CycloneDX JSON (1.4 to 1.6). Packages are components (nested ones
// included) with a purl; the OS is the component of type
// "operating-system" (Syft adds syft:distro:* properties to it with the
// full os-release). metadata.tools is an array in 1.4 and an object with
// components in 1.5+. Locations: Syft's syft:location:N:path properties,
// and 1.5 evidence occurrences.

type cdxComponent struct {
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Description string         `json:"description"`
	PURL        string         `json:"purl"`
	Properties  []cdxProperty  `json:"properties"`
	Components  []cdxComponent `json:"components"`
	Evidence    struct {
		Occurrences []struct {
			Location string `json:"location"`
		} `json:"occurrences"`
	} `json:"evidence"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxDoc struct {
	BOMFormat string `json:"bomFormat"`
	Metadata  struct {
		Timestamp string          `json:"timestamp"`
		Tools     json.RawMessage `json:"tools"`
	} `json:"metadata"`
	Components []cdxComponent `json:"components"`
}

func parseCycloneDX(b []byte) (*Document, error) {
	var d cdxDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("sbom: cyclonedx: %w", err)
	}
	if d.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("sbom: cyclonedx: bomFormat %q", d.BOMFormat)
	}
	doc := &Document{Format: FormatCycloneDX, Created: parseTime(d.Metadata.Timestamp)}
	doc.ToolName, doc.ToolVersion = pickTool(cdxTools(d.Metadata.Tools))

	var walk func([]cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			walk(c.Components)
			if c.Type == "operating-system" {
				if doc.OS.ID == "" {
					doc.OS = cdxOS(c)
				}
				continue
			}
			if c.PURL == "" {
				doc.Skipped++
				continue
			}
			u, err := purl.Parse(c.PURL)
			if err != nil {
				doc.Skipped++
				continue
			}
			var paths []string
			for _, p := range c.Properties {
				if strings.HasPrefix(p.Name, "syft:location:") && strings.HasSuffix(p.Name, ":path") {
					paths = append(paths, p.Value)
				}
			}
			for _, o := range c.Evidence.Occurrences {
				paths = append(paths, o.Location)
			}
			doc.Packages = append(doc.Packages, Package{PURL: u, Paths: cleanPaths(u.Type, paths)})
		}
	}
	walk(d.Components)
	if doc.OS.ID == "" {
		doc.OS = osFromPURLs(doc.Packages)
	}
	return doc, nil
}

// cdxTools reads metadata.tools in either shape.
func cdxTools(raw json.RawMessage) [][2]string {
	var list []cdxTool
	if err := json.Unmarshal(raw, &list); err != nil {
		var obj struct {
			Components []cdxTool `json:"components"`
			Services   []cdxTool `json:"services"`
		}
		if json.Unmarshal(raw, &obj) != nil {
			return nil
		}
		list = append(obj.Components, obj.Services...)
	}
	out := make([][2]string, 0, len(list))
	for _, t := range list {
		if t.Name != "" {
			out = append(out, [2]string{t.Name, t.Version})
		}
	}
	return out
}

// cdxOS reads an operating-system component: name and version are the
// os-release ID and VERSION_ID, refined by Syft's syft:distro:* properties.
func cdxOS(c cdxComponent) purl.OSRelease {
	o := purl.OSRelease{ID: strings.ToLower(c.Name), VersionID: c.Version, PrettyName: c.Description}
	for _, p := range c.Properties {
		switch p.Name {
		case "syft:distro:id":
			o.ID = strings.ToLower(p.Value)
		case "syft:distro:versionID":
			o.VersionID = p.Value
		case "syft:distro:versionCodename":
			o.VersionCodename = strings.ToLower(p.Value)
		case "syft:distro:prettyName":
			o.PrettyName = p.Value
		}
	}
	return o
}
