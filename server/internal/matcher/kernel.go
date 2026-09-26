package matcher

import (
	"regexp"
	"strings"
)

// Kernel handling (DOMAIN_MODEL.md §2.5, Q7).
//
// Advisories cite kernels by their *source* package: "linux",
// "linux-aws", "linux-hwe-6.8", "linux-oem-6.8", and on Debian "linux" or
// "linux-6.12". Installed kernel binaries often come from a wrapper
// source instead:
//
//	Ubuntu linux-image-6.8.0-45-generic   Source: linux-signed-hwe-6.8 (6.8.0-45.45~22.04.1)
//	Ubuntu linux-modules-6.8.0-45-generic Source: linux-hwe-6.8
//	Ubuntu linux-image-generic            Source: linux-meta (5.15.0.91.88)    metapackage
//	Debian linux-image-6.1.0-18-amd64     Source: linux-signed-amd64 (6.1.76+1), Version: 6.1.76-1
//	Debian linux-image-amd64              Source: linux-signed-amd64           metapackage
//
// Resolve strips the -signed / -meta / -restricted-modules wrappers to get
// the advisory source. For wrapper sources the source *version* is not the
// kernel's (Debian's signed source is "6.1.76+1", Ubuntu's meta source is
// "5.15.0.91.88"), so the binary's own version, which equals the kernel
// source version for image packages on both distros, is compared instead.
//
// Only kernel image and module binaries (linux-image-<release>,
// linux-image-unsigned-<release>, linux-modules[-extra]-<release>) are
// matched. They carry the kernel release they belong to in their name,
// which is exactly what the running kernel reports in
// /proc/sys/kernel/osrelease ("6.8.0-45-generic", "6.1.0-18-amd64"). Every
// other binary built from a kernel source (metapackages, headers, tools,
// linux-libc-dev, linux-doc, linux-source-*, Debian's bpftool/usbip/
// linux-cpupower, nvidia module packages) is not matched: it is not the
// kernel that runs, and matching it would raise every kernel CVE against,
// e.g., linux-libc-dev on a build host.
//
// Whether a matched kernel is the *running* one is per host, so it is not
// decided here: findings reconciliation raises findings only for kernel
// binaries whose KernelRelease equals the host's running kernel.

// Target is what the matcher evaluates for one interned binary version.
type Target struct {
	// Source and Version are the advisory source package and the version
	// to compare. Source "" means the binary is not matched at all.
	Source, Version string
	// KernelRelease is set for kernel image/module binaries: the kernel
	// release (uname -r) they belong to.
	KernelRelease string
}

// Binary is the part of a software_versions row Resolve needs.
type Binary struct {
	Ecosystem, Distro, Name, Version string
	Source, SourceVersion            string
	SourceInferred                   bool
}

// Resolve maps an interned binary version to what the matcher compares.
func Resolve(b Binary) Target {
	if b.Ecosystem != "deb" || b.Source == "" || b.SourceVersion == "" {
		return Target{}
	}
	if b.SourceInferred {
		// Older agents send no Source: field, so the source was defaulted to
		// the binary name. For ordinary packages that is often right (and
		// the host is flagged "matching may be incomplete"). A kernel
		// binary's source can't be derived from its name (a "-generic"
		// image may be linux or linux-hwe-X), so kernels from such agents
		// are not matched rather than matched against a guess.
		if _, ok := KernelRelease(b.Name); ok {
			return Target{}
		}
		return Target{Source: b.Source, Version: b.SourceVersion}
	}
	src, wrapped := KernelSource(b.Distro, b.Source)
	if !IsKernelSource(src) {
		return Target{Source: b.Source, Version: b.SourceVersion}
	}
	rel, ok := KernelRelease(b.Name)
	if !ok {
		return Target{} // metapackage, headers, tools, libc-dev, ...
	}
	v := b.SourceVersion
	if wrapped {
		v = b.Version
	}
	return Target{Source: src, Version: v, KernelRelease: rel}
}

var debianArches = map[string]bool{
	"amd64": true, "arm64": true, "i386": true, "armhf": true, "armel": true,
	"ppc64el": true, "s390x": true, "mips64el": true, "riscv64": true, "loong64": true,
}

// KernelSource strips a kernel wrapper source name down to the source that
// advisories cite. wrapped reports whether anything was stripped.
//
//	linux-signed                    -> linux
//	linux-signed-hwe-6.8            -> linux-hwe-6.8
//	linux-meta-aws                  -> linux-aws
//	linux-restricted-modules-oem-6.8 -> linux-oem-6.8
//	debian linux-signed-amd64       -> linux
//	debian linux-signed-6.12-amd64  -> linux-6.12
//
// Any other source is returned unchanged.
func KernelSource(distro, source string) (string, bool) {
	for _, w := range []string{"linux-signed", "linux-meta", "linux-restricted-modules", "linux-restricted-signatures"} {
		rest, ok := strings.CutPrefix(source, w)
		if !ok || (rest != "" && rest[0] != '-') {
			continue
		}
		rest = strings.TrimPrefix(rest, "-")
		if distro == "debian" {
			// Debian signs per architecture: linux-signed-<arch>, and for
			// backported/alternate kernels linux-signed-<ver>-<arch>.
			if i := strings.LastIndexByte(rest, '-'); i >= 0 && debianArches[rest[i+1:]] {
				rest = rest[:i]
			} else if debianArches[rest] {
				rest = ""
			}
		}
		if rest == "" {
			return "linux", true
		}
		return "linux-" + rest, true
	}
	return source, false
}

// nonKernelSources are "linux*" source packages that are not kernels.
var nonKernelSources = map[string]bool{
	"linux-atm": true, "linux-base": true, "linux-entra-sso": true, "linux-firmware": true,
	"linux-firmware-raspi": true, "linux-ftpd": true, "linux-ftpd-ssl": true,
	"linux-igd": true, "linux-sound-base": true, "linux-apfs-rw": true,
	"linux-wlan-ng": true, "linux-show-player": true, "linux-user-chroot": true,
	"linux-minidisc": true,
}

// binaryLike are prefixes of kernel *binary* names; a source named like
// this is an inferred (binary-named) source, not a kernel source.
var binaryLike = []string{"linux-image-", "linux-modules-", "linux-headers-", "linux-tools-",
	"linux-cloud-tools-", "linux-buildinfo-", "linux-libc-dev", "linux-source-", "linux-doc"}

// IsKernelSource reports whether an (already unwrapped) source package is
// a Linux kernel: "linux" or "linux-<flavour>[-<version>]".
func IsKernelSource(src string) bool {
	if src == "linux" {
		return true
	}
	if !strings.HasPrefix(src, "linux-") || nonKernelSources[src] {
		return false
	}
	for _, p := range binaryLike {
		if strings.HasPrefix(src, p) {
			return false
		}
	}
	return true
}

// kernelBinaryRe matches kernel image/module binary names and captures the
// kernel release. The release starts with a digit and a dot ("6.8.0-45-
// generic", "6.1.0-18-amd64", "6.12.48+deb13-amd64"), which keeps
// linux-modules-nvidia-535-<release> and metapackages out.
var kernelBinaryRe = regexp.MustCompile(`^linux-(?:image|image-unsigned|modules|modules-extra)-([0-9]+\.[0-9]+[^\s]*)$`)

// KernelRelease extracts the kernel release from a kernel image or module
// binary name. Debian's "-unsigned" image suffix is dropped; debug-symbol
// packages (-dbg, -dbgsym) are not kernels.
func KernelRelease(binary string) (string, bool) {
	m := kernelBinaryRe.FindStringSubmatch(binary)
	if m == nil {
		return "", false
	}
	rel := m[1]
	if strings.HasSuffix(rel, "-dbg") || strings.HasSuffix(rel, "-dbgsym") {
		return "", false
	}
	return strings.TrimSuffix(rel, "-unsigned"), true
}

// RaisesFinding decides the running-vs-installed policy (Q7) for one
// matched binary on one host. Non-kernel binaries always raise findings.
// A kernel binary raises findings only when it belongs to the running
// kernel. When the running kernel is unknown (agents older than the
// kernel collector, or a failed collector), every installed kernel raises
// findings: unknown must not hide risk, and those findings are flagged
// running_kernel_unknown so the UI can say why.
func RaisesFinding(kernelRelease, runningKernel string) (raise, runningUnknown bool) {
	if kernelRelease == "" {
		return true, false
	}
	if runningKernel == "" {
		return true, true
	}
	return kernelRelease == runningKernel, false
}
