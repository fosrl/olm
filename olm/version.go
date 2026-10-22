package olm

import (
	"runtime/debug"
	"strings"
)

// olmModulePath is the module path of this package, used to find its version
// in the build info of a binary that embeds olm (the CLI, Pangolin Windows, ...).
const olmModulePath = "github.com/fosrl/olm"

// resolveOlmVersion returns the version of the olm module this binary was
// built with, as opposed to config.Version which is the embedding agent's
// version. It prefers config.OlmVersion, then the module version from the
// binary's build info, and returns "" if neither is available.
func resolveOlmVersion(config OlmConfig) string {
	if config.OlmVersion != "" {
		return config.OlmVersion
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == olmModulePath {
				return strings.TrimPrefix(dep.Version, "v")
			}
		}
	}

	return ""
}
