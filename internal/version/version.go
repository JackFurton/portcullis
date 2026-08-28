// Package version reports what build this is.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Version is set at build time with -ldflags. It falls back to the module
// version when the binary was installed with "go install", and to "dev" when
// it was built from a working tree.
var Version = ""

// String renders the version, the commit it was built from, and the toolchain.
func String() string {
	version, revision, dirty := build()
	if dirty {
		revision += "-dirty"
	}
	return fmt.Sprintf("%s (%s) %s %s/%s", version, revision, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func build() (version, revision string, dirty bool) {
	version, revision = Version, "unknown"

	info, ok := debug.ReadBuildInfo()
	if !ok {
		if version == "" {
			version = "dev"
		}
		return version, revision, false
	}
	if version == "" {
		version = info.Main.Version
		if version == "" || version == "(devel)" {
			version = "dev"
		}
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if len(setting.Value) >= 12 {
				revision = setting.Value[:12]
			} else {
				revision = setting.Value
			}
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	return version, revision, dirty
}
