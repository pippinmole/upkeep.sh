package inventory

import (
	"slices"
	"testing"
)

func items() []Item {
	return []Item{
		{Name: "libssl3", Version: "3.0.2-0ubuntu1.15", Arch: "amd64", Source: "openssl", SourceVersion: "3.0.2-0ubuntu1.15"},
		{Name: "bash", Version: "5.1-6ubuntu1", Arch: "amd64", Source: "bash", SourceVersion: "5.1-6ubuntu1"},
		{Name: "tzdata", Version: "2024a-0ubuntu0.22.04", Arch: "all", Source: "tzdata", SourceVersion: "2024a-0ubuntu0.22.04"},
	}
}

func TestHashIsOrderIndependentAndDeduplicated(t *testing.T) {
	a := NewSet("deb", "ubuntu", "jammy", items())

	rev := items()
	slices.Reverse(rev)
	rev = append(rev, rev[0]) // exact duplicate
	b := NewSet("deb", "ubuntu", "jammy", rev)

	if a.Hash != b.Hash {
		t.Fatalf("hash depends on order/duplicates: %s vs %s", a.Hash, b.Hash)
	}
	if len(b.Items) != 3 {
		t.Fatalf("duplicates not removed: %d items", len(b.Items))
	}
	if !slices.IsSortedFunc(b.Items, compareItems) {
		t.Fatal("items not sorted")
	}
}

func TestHashChangesWithEveryField(t *testing.T) {
	base := NewSet("deb", "ubuntu", "jammy", items()).Hash
	mutations := map[string]func() Set{
		"ecosystem": func() Set { return NewSet("rpm", "ubuntu", "jammy", items()) },
		"distro":    func() Set { return NewSet("deb", "debian", "jammy", items()) },
		"release":   func() Set { return NewSet("deb", "ubuntu", "noble", items()) },
		"version": func() Set {
			it := items()
			it[0].Version = "3.0.2-0ubuntu1.16"
			return NewSet("deb", "ubuntu", "jammy", it)
		},
		"arch": func() Set {
			it := items()
			it[1].Arch = "arm64"
			return NewSet("deb", "ubuntu", "jammy", it)
		},
		"source": func() Set {
			it := items()
			it[0].Source = "libssl3"
			return NewSet("deb", "ubuntu", "jammy", it)
		},
		"source_version": func() Set {
			it := items()
			it[0].SourceVersion = "3.0.2-0ubuntu1.14"
			return NewSet("deb", "ubuntu", "jammy", it)
		},
		"inferred": func() Set {
			it := items()
			it[1].SourceInferred = true
			return NewSet("deb", "ubuntu", "jammy", it)
		},
		"removed": func() Set { return NewSet("deb", "ubuntu", "jammy", items()[:2]) },
	}
	seen := map[string]string{base: "base"}
	for name, m := range mutations {
		h := m().Hash
		if prev, dup := seen[h]; dup {
			t.Errorf("mutation %q hashes the same as %q", name, prev)
		}
		seen[h] = name
	}
}

func TestHashFieldBoundaries(t *testing.T) {
	// Field separators must prevent ("ab","c") colliding with ("a","bc").
	a := NewSet("deb", "", "", []Item{{Name: "ab", Version: "c"}})
	b := NewSet("deb", "", "", []Item{{Name: "a", Version: "bc"}})
	if a.Hash == b.Hash {
		t.Fatal("field boundary collision")
	}
}

func TestEmptySet(t *testing.T) {
	s := NewSet("deb", "ubuntu", "jammy", nil)
	if s.Items == nil || len(s.Items) != 0 {
		t.Fatalf("want empty non-nil items, got %#v", s.Items)
	}
	if s.Hash == "" || s.Hash == NewSet("deb", "ubuntu", "jammy", items()).Hash {
		t.Fatal("empty set needs its own hash")
	}
}

func TestDuplicateKeyPrefersRealSource(t *testing.T) {
	s := NewSet("deb", "ubuntu", "jammy", []Item{
		{Name: "libssl3", Version: "1", Arch: "amd64", Source: "libssl3", SourceVersion: "1", SourceInferred: true},
		{Name: "libssl3", Version: "1", Arch: "amd64", Source: "libssl3", SourceVersion: "1"},
	})
	if len(s.Items) != 1 || s.Items[0].SourceInferred {
		t.Fatalf("got %#v", s.Items)
	}
}

func TestDiff(t *testing.T) {
	cases := []struct {
		name                  string
		open, reported        []int64
		wantAdded, wantRemove []int64
	}{
		{"first push", nil, []int64{3, 1, 2}, []int64{1, 2, 3}, nil},
		{"unchanged", []int64{1, 2}, []int64{2, 1}, nil, nil},
		{"upgrade is close+open", []int64{1, 2}, []int64{1, 5}, []int64{5}, []int64{2}},
		{"authoritative empty closes all", []int64{1, 2}, nil, nil, []int64{1, 2}},
		{"duplicates tolerated", []int64{1, 1}, []int64{1, 4, 4}, []int64{4}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, r := Diff(c.open, c.reported)
			if !slices.Equal(a, c.wantAdded) || !slices.Equal(r, c.wantRemove) {
				t.Fatalf("Diff(%v, %v) = +%v -%v, want +%v -%v", c.open, c.reported, a, r, c.wantAdded, c.wantRemove)
			}
		})
	}
}
