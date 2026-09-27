package sshkey

import "testing"

// A real ed25519 public key (generated for this test, private half discarded).
const ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDOgzQA+0gYe3bNWRpmy4dc9UnFnDWFNyKwS53m2CEb3"

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		ed:                          ed,
		ed + " upkeep-agent@web-1":  ed,
		"  " + ed + "  \n":          ed,
		ed + " comment with spaces": ed,
	}
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"",
		"ssh-ed25519",
		"ssh-dss AAAAB3NzaC1kc3MAAACBAP", // unsupported type
		"ssh-ed25519 !!!notbase64",       // bad base64
		"ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIDOgzQA+0gYe3bNWRpmy4dc9UnFnDWFNyKwS53m2CEb3", // blob type mismatch
		"ssh-ed25519 AAAA",         // truncated
		`command="rm -rf /" ` + ed, // options are not a key
	}
	for _, in := range bad {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want error", in, got)
		}
	}
}
