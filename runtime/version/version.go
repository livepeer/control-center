// Package version identifies the executing Runtime binary.
package version

import (
	"runtime/debug"

	"github.com/livepeer/control-center/runtime/contract"
)

// Set by release builds; empty fields remain unknown on unversioned builds.
var Version, Commit string

func Current() contract.BuildIdentity {
	v := contract.BuildIdentity{Version: Version, Commit: Commit}
	if b, ok := debug.ReadBuildInfo(); ok {
		if v.Version == "" && b.Main.Version != "(devel)" {
			v.Version = b.Main.Version
		}
		for _, s := range b.Settings {
			if s.Key == "vcs.revision" && v.Commit == "" {
				v.Commit = s.Value
			}
			if s.Key == "vcs.modified" {
				v.Modified = s.Value == "true"
			}
		}
	}
	return v
}
