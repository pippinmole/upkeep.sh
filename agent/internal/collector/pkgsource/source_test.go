package pkgsource

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/pippinmole/upkeep.sh/agent/internal/collector"
	"github.com/pippinmole/upkeep.sh/agent/internal/detect"
	"github.com/pippinmole/upkeep.sh/agent/internal/target"
)

// fakeSource is a Source with canned applicability and results.
type fakeSource struct {
	name, ecosystem string
	applies         func(detect.OS) bool
	pkgs            []collector.Package
	err             error
}

func (f fakeSource) Name() string             { return f.name }
func (f fakeSource) Ecosystem() string        { return f.ecosystem }
func (f fakeSource) Applies(o detect.OS) bool { return f.applies(o) }
func (f fakeSource) Collect(context.Context, target.Target) ([]collector.Package, error) {
	return f.pkgs, f.err
}

func familyIs(fam detect.Family) func(detect.OS) bool {
	return func(o detect.OS) bool { return o.Family == fam }
}

var (
	ubuntu  = detect.OS{Family: detect.FamilyLinux, ID: "ubuntu", IDLike: []string{"debian"}}
	alpine  = detect.OS{Family: detect.FamilyLinux, ID: "alpine"}
	windows = detect.OS{Family: detect.FamilyWindows}
)

func names(srcs []Source) []string {
	var out []string
	for _, s := range srcs {
		out = append(out, s.Name())
	}
	return out
}

func TestRegistryApplicable(t *testing.T) {
	reg := NewRegistry(
		Dpkg{},
		fakeSource{name: "win_programs", applies: familyIs(detect.FamilyWindows)},
		fakeSource{name: "any_linux", applies: familyIs(detect.FamilyLinux)},
	)
	tests := []struct {
		name string
		os   detect.OS
		want []string
	}{
		{"ubuntu selects dpkg and generic linux", ubuntu, []string{"deb_packages", "any_linux"}},
		{"alpine selects no dpkg", alpine, []string{"any_linux"}},
		{"windows selects only windows", windows, []string{"win_programs"}},
		{"undetected selects nothing", detect.OS{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := names(reg.Applicable(tt.os)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultRegistry(t *testing.T) {
	if got := names(Default().Applicable(ubuntu)); !reflect.DeepEqual(got, []string{"deb_packages"}) {
		t.Errorf("ubuntu: got %v, want [deb_packages]", got)
	}
	for _, o := range []detect.OS{alpine, windows, {Family: detect.FamilyMacOS}, {}} {
		if got := Default().Applicable(o); len(got) != 0 {
			t.Errorf("%+v: got %v, want no sources", o, names(got))
		}
	}
}

func TestNewRegistryRejectsDuplicateNames(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate source name")
		}
	}()
	NewRegistry(Dpkg{}, Dpkg{})
}

func TestRegistryCollectStatus(t *testing.T) {
	linux := familyIs(detect.FamilyLinux)
	okSrc := fakeSource{
		name: "good", ecosystem: "deb", applies: linux,
		pkgs: []collector.Package{{Name: "a", Version: "1"}},
	}
	emptySrc := fakeSource{name: "empty", ecosystem: "apk", applies: linux, pkgs: nil}
	badSrc := fakeSource{
		name: "bad", ecosystem: "rpm", applies: linux,
		// A failing source's partial results must never leak through.
		pkgs: []collector.Package{{Name: "partial"}}, err: errors.New("database locked"),
	}
	winSrc := fakeSource{name: "win", ecosystem: "windows", applies: familyIs(detect.FamilyWindows)}

	tests := []struct {
		name       string
		sources    []Source
		os         detect.OS
		wantPkgs   []collector.Package
		wantStatus map[string]collector.CollectorStatus
	}{
		{
			name:     "one source fails, others still reported",
			sources:  []Source{okSrc, badSrc, winSrc},
			os:       ubuntu,
			wantPkgs: []collector.Package{{Name: "a", Version: "1", Ecosystem: "deb"}},
			wantStatus: map[string]collector.CollectorStatus{
				"good": {Status: collector.StatusOK},
				"bad":  {Status: collector.StatusError, Error: "database locked"},
				"win":  {Status: collector.StatusSkipped, Reason: "not applicable to linux (ubuntu)"},
			},
		},
		{
			name:     "only source fails: packages null, not empty",
			sources:  []Source{badSrc},
			os:       ubuntu,
			wantPkgs: nil,
			wantStatus: map[string]collector.CollectorStatus{
				"bad": {Status: collector.StatusError, Error: "database locked"},
			},
		},
		{
			name:     "ok but empty: packages is [] not null",
			sources:  []Source{emptySrc},
			os:       ubuntu,
			wantPkgs: []collector.Package{},
			wantStatus: map[string]collector.CollectorStatus{
				"empty": {Status: collector.StatusOK},
			},
		},
		{
			name:     "nothing applicable",
			sources:  []Source{okSrc, winSrc},
			os:       detect.OS{},
			wantPkgs: nil,
			wantStatus: map[string]collector.CollectorStatus{
				"good": {Status: collector.StatusSkipped, Reason: "not applicable to undetected OS"},
				"win":  {Status: collector.StatusSkipped, Reason: "not applicable to undetected OS"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, status := NewRegistry(tt.sources...).Collect(context.Background(), target.NewLocal(t.TempDir(), ""), tt.os)
			if !reflect.DeepEqual(pkgs, tt.wantPkgs) {
				t.Errorf("pkgs = %#v, want %#v", pkgs, tt.wantPkgs)
			}
			if !reflect.DeepEqual(status, tt.wantStatus) {
				t.Errorf("status = %+v, want %+v", status, tt.wantStatus)
			}
		})
	}
}
