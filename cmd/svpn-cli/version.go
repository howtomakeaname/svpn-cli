package main

import (
	"fmt"
	"runtime"
)

// Set by the release build; local development builds remain identifiable.
var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

func versionString() string {
	return fmt.Sprintf("svpn-cli %s (%s; %s/%s; %s)", version, commit, runtime.GOOS, runtime.GOARCH, buildDate)
}
