package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/image"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi/dockerapitest"
)

func TestCollectDockerImages(t *testing.T) {
	pg, dangling := "sha256:"+dockerID(1), "sha256:"+dockerID(2)
	f := &dockerapitest.Fake{
		Images: []image.Summary{
			{ID: dangling, Created: 1700000000, RepoTags: []string{"<none>:<none>"}, RepoDigests: []string{"<none>@<none>"}},
			{ID: pg, Labels: map[string]string{
				"org.opencontainers.image.version": "18.0",
				"maintainer":                       "someone",
				"com.example.token":                "hunter2",
			}},
		},
		ImageInspects: map[string]image.InspectResponse{
			pg: {
				ID:           pg,
				RepoTags:     []string{"postgres:18", "postgres:latest", "postgres:18"},
				RepoDigests:  []string{"postgres@sha256:abc"},
				Created:      "2026-09-01T08:30:00.5+01:00",
				Os:           "linux",
				Architecture: "arm",
				Variant:      "v7",
				RootFS:       image.RootFS{Type: "layers", Layers: []string{"sha256:base", "sha256:mid", "sha256:app"}},
			},
			dangling: {ID: dangling, RepoTags: []string{"<none>:<none>"}, RepoDigests: []string{"<none>@<none>"},
				Os: "linux", Architecture: "amd64"},
		},
	}
	// The image config holds Env and Cmd, which must never be read.
	pgInspect := f.ImageInspects[pg]
	if err := json.Unmarshal([]byte(`{"Config":{"Env":["PGPASSWORD=hunter2"],"Cmd":["postgres"],`+
		`"Labels":{"org.opencontainers.image.version":"18.0","com.example.token":"hunter2"}}}`), &pgInspect); err != nil {
		t.Fatal(err)
	}
	f.ImageInspects[pg] = pgInspect

	got, truncated, err := CollectDockerImages(context.Background(), f)
	if err != nil || truncated {
		t.Fatalf("truncated %v, err %v", truncated, err)
	}
	want := []DockerImage{
		{
			ID: pg, RepoTags: []string{"postgres:18", "postgres:latest"}, RepoDigests: []string{"postgres@sha256:abc"},
			Created: "2026-09-01T07:30:00Z", OS: "linux", Arch: "arm", Variant: "v7",
			Layers: []string{"sha256:base", "sha256:mid", "sha256:app"}, // chain order, not sorted
			Labels: map[string]string{"org.opencontainers.image.version": "18.0"},
		},
		// Dangling: no placeholders; created falls back to the list's.
		{ID: dangling, Created: "2023-11-14T22:13:20Z", OS: "linux", Arch: "amd64"},
	}
	// Sorted by id: pg (…01) before dangling (…02).
	if !reflect.DeepEqual(got, want) {
		gb, _ := json.MarshalIndent(got, "", " ")
		t.Errorf("images =\n%s", gb)
	}
	b, _ := json.Marshal(got)
	for _, s := range []string{"hunter2", "PGPASSWORD", "maintainer", "<none>"} {
		if strings.Contains(string(b), s) {
			t.Errorf("payload contains %q: %s", s, b)
		}
	}
}

func TestCollectDockerImagesDisappearedAndErrors(t *testing.T) {
	a, gone := "sha256:a", "sha256:gone"
	f := &dockerapitest.Fake{
		Images:        []image.Summary{{ID: gone}, {ID: a}},
		ImageInspects: map[string]image.InspectResponse{a: {ID: a}},
	}
	got, truncated, err := CollectDockerImages(context.Background(), f)
	if err != nil || truncated || len(got) != 1 || got[0].ID != a {
		t.Errorf("disappeared: got %+v, truncated %v, err %v", got, truncated, err)
	}

	// A failed inspect keeps the image as a partial entry from its list
	// data; the collector stays ok.
	f.ImageInspectErr = errors.New("boom")
	f.Images = []image.Summary{{ID: a, Created: 1700000000, RepoTags: []string{"<none>:<none>", "b:1", "a:1"},
		RepoDigests: []string{"<none>@<none>"}, Labels: map[string]string{"org.opencontainers.image.source": "x", "k": "v"}}}
	got, truncated, err = CollectDockerImages(context.Background(), f)
	want := []DockerImage{{ID: a, RepoTags: []string{"a:1", "b:1"}, Created: "2023-11-14T22:13:20Z",
		Labels: map[string]string{"org.opencontainers.image.source": "x"}, InspectError: "boom"}}
	if err != nil || truncated || !reflect.DeepEqual(got, want) {
		t.Errorf("inspect error: got %+v, truncated %v, err %v", got, truncated, err)
	}
	// Its list data is capped like a full entry's.
	tags := make([]string, MaxDockerRepoTagsPerImage+1)
	for i := range tags {
		tags[i] = fmt.Sprintf("r:%03d", i)
	}
	f.Images[0].RepoTags = tags
	if got, truncated, err := CollectDockerImages(context.Background(), f); err != nil || !truncated || len(got[0].RepoTags) != MaxDockerRepoTagsPerImage {
		t.Errorf("partial caps: truncated %v, err %v", truncated, err)
	}
	f.ImagesErr = errors.New("boom")
	if _, _, err := CollectDockerImages(context.Background(), f); err == nil || !strings.Contains(err.Error(), "docker image list") {
		t.Errorf("list error: %v", err)
	}
}

func TestCollectDockerImagesCaps(t *testing.T) {
	f := &dockerapitest.Fake{ImageInspects: map[string]image.InspectResponse{}}
	for i := MaxDockerImages; i >= 0; i-- {
		id := "sha256:" + dockerID(i)
		f.Images = append(f.Images, image.Summary{ID: id})
		f.ImageInspects[id] = image.InspectResponse{ID: id}
	}
	got, truncated, err := CollectDockerImages(context.Background(), f)
	if err != nil || !truncated || len(got) != MaxDockerImages || got[0].ID != "sha256:"+dockerID(0) {
		t.Errorf("top-level cap: %d images, truncated %v, err %v", len(got), truncated, err)
	}

	var tags, digests, layers []string
	for i := range MaxDockerLayersPerImage + 1 {
		tags = append(tags, fmt.Sprintf("r:%03d", i))
		digests = append(digests, fmt.Sprintf("r@sha256:%03d", i))
		layers = append(layers, fmt.Sprintf("sha256:%03d", MaxDockerLayersPerImage-i)) // descending: must not be sorted
	}
	for name, in := range map[string]image.InspectResponse{
		"tags":    {RepoTags: tags},
		"digests": {RepoDigests: digests},
		"layers":  {RootFS: image.RootFS{Layers: layers}},
	} {
		img, cut := dockerImage(image.Summary{ID: "x"}, in)
		if !cut {
			t.Errorf("%s: not cut", name)
		}
		switch name {
		case "tags":
			if len(img.RepoTags) != MaxDockerRepoTagsPerImage || img.RepoTags[0] != "r:000" {
				t.Errorf("tags = %d, first %q", len(img.RepoTags), img.RepoTags[0])
			}
		case "digests":
			if len(img.RepoDigests) != MaxDockerRepoDigestsPerImage || img.RepoDigests[0] != "r@sha256:000" {
				t.Errorf("digests = %d", len(img.RepoDigests))
			}
		case "layers":
			if len(img.Layers) != MaxDockerLayersPerImage || img.Layers[0] != layers[0] || img.Layers[len(img.Layers)-1] != layers[MaxDockerLayersPerImage-1] {
				t.Errorf("layers = %d, %s..%s", len(img.Layers), img.Layers[0], img.Layers[len(img.Layers)-1])
			}
		}
	}
}
