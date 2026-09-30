package alerting

import (
	"fmt"
	"strings"
)

// Alert titles: one line about one alert instance, without the host (the
// channels add " on <host>"). Kept here so they are tested without a
// database; store/alertrules_eval.go calls them.

// PortTitle: "Port 22/tcp is listening"; with allowlist (operator not_in)
// "Port 8080/tcp is listening (not allowed)".
func PortTitle(transport string, port int, allowlist bool) string {
	s := fmt.Sprintf("Port %d/%s is listening", port, transport)
	if allowlist {
		s += " (not allowed)"
	}
	return s
}

// PortSubject is a listening_port instance's subject: "tcp/22".
func PortSubject(transport string, port int) string { return fmt.Sprintf("%s/%d", transport, port) }

// PackageTitle: "Package telnetd is installed" / "Package fail2ban is not
// installed".
func PackageTitle(name string, installed bool) string {
	if installed {
		return "Package " + name + " is installed"
	}
	return "Package " + name + " is not installed"
}

// OSName is "ubuntu 22.04", or the family when the id is unknown.
func OSName(id, version, family string) string {
	name := id
	if name == "" {
		name = family
	}
	if version != "" {
		name += " " + version
	}
	return name
}

// OSTitle: "OS is ubuntu 22.04" (in) / "OS ubuntu 22.04 is not allowed"
// (not_in).
func OSTitle(name string, notIn bool) string {
	if notIn {
		return "OS " + name + " is not allowed"
	}
	return "OS is " + name
}

// RebootTitle is the reboot_required title.
const RebootTitle = "Reboot required"

// VulnTitle: "KEV CVE-2024-3094 in xz-utils", "Critical CVE-2024-1 in
// openssl (image nginx:1.25)".
func VulnTitle(vulnKey, pkg, severity string, kev bool, image string) string {
	prefix := ""
	switch {
	case kev:
		prefix = "KEV "
	case severity != "":
		prefix = strings.ToUpper(severity[:1]) + severity[1:] + " "
	}
	s := prefix + vulnKey
	if pkg != "" {
		s += " in " + pkg
	}
	if image != "" {
		s += " (image " + image + ")"
	}
	return s
}

// NotSeenTitle: "Not seen for more than 30 minutes" (hours and days when
// they divide evenly).
func NotSeenTitle(minutes int) string {
	return "Not seen for more than " + DurationWords(minutes)
}

// DurationWords renders minutes as "30 minutes", "2 hours", "1 day".
func DurationWords(minutes int) string {
	unit := func(n int, s string) string {
		if n == 1 {
			return "1 " + s
		}
		return fmt.Sprintf("%d %ss", n, s)
	}
	switch {
	case minutes%1440 == 0:
		return unit(minutes/1440, "day")
	case minutes%60 == 0:
		return unit(minutes/60, "hour")
	}
	return unit(minutes, "minute")
}

// CollectorTitle: "Collector deb_packages failed".
func CollectorTitle(name string) string { return "Collector " + name + " failed" }
