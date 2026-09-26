package collector

import (
	"bufio"
	"io"
	"os"
	"strings"
)

const DefaultOSReleasePath = "/host/etc/os-release"

func CollectOSRelease(path string) (OSRelease, error) {
	f, err := os.Open(path)
	if err != nil {
		return OSRelease{}, err
	}
	defer f.Close()
	return parseOSRelease(f)
}

func parseOSRelease(r io.Reader) (OSRelease, error) {
	fields := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[k] = strings.Trim(v, `"`)
	}
	if err := sc.Err(); err != nil {
		return OSRelease{}, err
	}
	return OSRelease{
		ID:        fields["ID"],
		VersionID: fields["VERSION_ID"],
		Codename:  fields["VERSION_CODENAME"],
	}, nil
}
