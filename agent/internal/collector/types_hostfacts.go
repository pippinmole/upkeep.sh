package collector

// Payload size caps. A section that hits its cap is sent sorted by key and
// cut to the cap, and its collector status is flagged truncated (see
// CollectorStatus.Truncated).
const (
	MaxListenersPerTransport = 1000
	MaxServices              = 2000
	MaxUsers                 = 2000
	MaxDeletedLibProcesses   = 200
	MaxDeletedLibsPerProcess = 20
)

// Service is one service known to the host's service manager. Only
// systemd is implemented; the shape is shared with the planned Windows SCM
// and launchd collectors (DOMAIN_MODEL.md §4.5, host_services).
type Service struct {
	Manager     string `json:"manager"` // "systemd"
	Name        string `json:"name"`    // unit name, "ssh.service"
	DisplayName string `json:"display_name,omitempty"`
	// StartMode is "auto" (starts at boot), "manual" (started on demand by
	// an enabled socket/timer/path unit), "disabled", "static" (no
	// [Install] section; only runs as a dependency) or "masked".
	StartMode string `json:"start_mode"`
	// State is "running" or "stopped"; omitted when the target has no
	// live procfs to tell.
	State      string         `json:"state,omitempty"`
	RunAs      string         `json:"run_as,omitempty"`
	BinaryPath string         `json:"binary_path,omitempty"`
	Attrs      map[string]any `json:"attrs,omitempty"`
}

// User is one local account from /etc/passwd with its group memberships
// from /etc/group. Password hashes (/etc/shadow) are never read.
type User struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Home  string `json:"home,omitempty"`
	Shell string `json:"shell,omitempty"`
	// Groups: the primary group first, then supplementary groups, sorted.
	Groups []string `json:"groups,omitempty"`
	// LoginShell: the shell is interactive (not nologin, false, sync, ...).
	LoginShell bool `json:"login_shell"`
	// Admin: uid 0, or a member of sudo, wheel, adm or admin.
	Admin bool `json:"admin"`
}

// Facts is the snapshot's facts block (snapshots.facts on the server).
type Facts struct {
	NeedsRestart       *NeedsRestart       `json:"needs_restart,omitempty"`
	UnattendedUpgrades *UnattendedUpgrades `json:"unattended_upgrades,omitempty"`
}

// NeedsRestart lists processes that still map a shared library deleted
// from disk (typically replaced by an upgrade): they keep running the old,
// possibly vulnerable code until restarted. Owned by "deleted_libs".
type NeedsRestart struct {
	Processes []DeletedLibProcess `json:"processes"`
	Truncated bool                `json:"truncated,omitempty"`
	// UnreadableProcesses counts processes whose maps could not be read
	// (reading another user's /proc/<pid>/maps needs CAP_SYS_PTRACE, which
	// the agent does not have). The list is complete only when this is 0.
	UnreadableProcesses int `json:"unreadable_processes"`
}

type DeletedLibProcess struct {
	PID       int      `json:"pid"`
	Name      string   `json:"name"`
	Unit      string   `json:"unit,omitempty"` // systemd service the process runs under
	Libraries []string `json:"libraries"`      // sorted, capped at MaxDeletedLibsPerProcess
}

// UnattendedUpgrades is Debian/Ubuntu automatic-update state. Owned by
// "unattended_upgrades".
type UnattendedUpgrades struct {
	// PackageInstalled is whether the unattended-upgrades package is
	// installed; omitted when the package inventory wasn't collected.
	PackageInstalled *bool `json:"package_installed,omitempty"`
	// UpdatePackageLists and UnattendedUpgrade are the raw
	// APT::Periodic::Update-Package-Lists / ::Unattended-Upgrade values
	// (an interval in days, "0" = off) after reading all of apt.conf.d.
	UpdatePackageLists string `json:"update_package_lists,omitempty"`
	UnattendedUpgrade  string `json:"unattended_upgrade,omitempty"`
	// Enabled: UnattendedUpgrade is a non-zero interval and the package is
	// not known to be missing.
	Enabled bool `json:"enabled"`
	// LastAptUpdate is when the package lists were last refreshed
	// (RFC3339), taken from LastAptUpdateSource: "update-success-stamp"
	// (APT's periodic stamp) or "lists" (mtime of /var/lib/apt/lists).
	LastAptUpdate       string `json:"last_apt_update,omitempty"`
	LastAptUpdateSource string `json:"last_apt_update_source,omitempty"`
	// LastUnattendedRun is the mtime of
	// /var/lib/apt/periodic/unattended-upgrades-stamp (RFC3339).
	LastUnattendedRun string `json:"last_unattended_run,omitempty"`
}
