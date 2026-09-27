package collector

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/moby/moby/api/types/image"

	"github.com/pippinmole/upkeep.sh/agent/internal/dockerapi"
)

// CollectDockerImages lists the engine's images (GET /images/json),
// inspects each one for its platform and layers, and maps it onto
// DockerImage. truncated is true when the image list or any image's tags,
// digests or layers hit their cap.
//
// Like containers: sorted by id and cut to MaxDockerImages before any
// inspect; an image removed between the list and its inspect is skipped;
// any other inspect failure fails the collector (dockerInspectAll).
//
// Labels come from the list entry (the image config's labels, through
// FilterDockerLabels), so the inspect's Config, which holds the image's
// Env, Cmd and Entrypoint, is never read.
func CollectDockerImages(ctx context.Context, c dockerapi.Client) (images []DockerImage, truncated bool, err error) {
	lctx, cancel := context.WithTimeout(ctx, DockerCallTimeout)
	list, err := c.ImageList(lctx)
	cancel()
	if err != nil {
		return nil, false, fmt.Errorf("docker image list: %w", err)
	}

	slices.SortFunc(list, func(a, b image.Summary) int { return cmp.Compare(a.ID, b.ID) })
	list = slices.CompactFunc(list, func(a, b image.Summary) bool { return a.ID == b.ID })
	if len(list) > MaxDockerImages {
		list, truncated = list[:MaxDockerImages], true
	}
	ids := make([]string, len(list))
	for i, s := range list {
		ids[i] = s.ID
	}
	inspects, found, err := dockerInspectAll(ctx, "image", ids, c.ImageInspect)
	if err != nil {
		return nil, false, err
	}

	images = make([]DockerImage, 0, len(list))
	for i, s := range list {
		if !found[i] {
			continue
		}
		img, cut := dockerImage(s, inspects[i])
		truncated = truncated || cut
		images = append(images, img)
	}
	return images, truncated, nil
}

// Placeholders the engine reports for an untagged (dangling) image or one
// pulled without a digest; not references.
const (
	danglingRepoTag    = "<none>:<none>"
	danglingRepoDigest = "<none>@<none>"
)

func dockerImage(s image.Summary, in image.InspectResponse) (DockerImage, bool) {
	out := DockerImage{
		ID:      s.ID,
		Created: dockerTime(in.Created),
		OS:      in.Os,
		Arch:    in.Architecture,
		Labels:  FilterDockerLabels(s.Labels),
	}
	if out.Created == "" && s.Created > 0 {
		out.Created = time.Unix(s.Created, 0).UTC().Format(time.RFC3339)
	}
	var tagsCut, digestsCut, layersCut bool
	out.RepoTags, tagsCut = dockerRefs(in.RepoTags, danglingRepoTag, MaxDockerRepoTagsPerImage)
	out.RepoDigests, digestsCut = dockerRefs(in.RepoDigests, danglingRepoDigest, MaxDockerRepoDigestsPerImage)
	// Layer order is the chain, base first: not sorted, and a cut keeps
	// the base-most layers (MaxDockerLayersPerImage).
	out.Layers, layersCut = capList(slices.Clone(in.RootFS.Layers), MaxDockerLayersPerImage)
	return out, tagsCut || digestsCut || layersCut
}

// dockerRefs drops the engine's placeholder and empty entries, then sorts,
// dedupes and caps what's left.
func dockerRefs(refs []string, placeholder string, max int) ([]string, bool) {
	var out []string
	for _, r := range refs {
		if r != "" && r != placeholder {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	return capList(out, max)
}
