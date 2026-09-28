package matcher

import "testing"

// Subset of the Alpine branch's TestAssessed (deb only here).
func TestAssessed(t *testing.T) {
	tests := []struct {
		eco, distro, release string
		want                 bool
	}{
		{"deb", "debian", "bookworm", true},
		{"deb", "ubuntu", "jammy", true},
		{"deb", "debian", "", false}, // release unknown: can't join per-release advisories
		{"deb", "alpine", "3.22", false},
		{"rpm", "rhel", "9", false},
		{"npm", "", "", false},
		{"homebrew", "", "", false},
	}
	for _, tt := range tests {
		if got := Assessed(tt.eco, tt.distro, tt.release); got != tt.want {
			t.Errorf("Assessed(%q, %q, %q) = %v, want %v", tt.eco, tt.distro, tt.release, got, tt.want)
		}
	}
}
