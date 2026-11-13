package main

import (
	"flag"
	"github.com/howtomakeaname/svpn-cli/internal/headers"
)

type headerFlags struct{ profilePath, userAgent *string }

func addHeaderFlags(f *flag.FlagSet) headerFlags {
	return headerFlags{
		f.String("header-profile", "", "JSON profile for User-Agent and additional control/gateway headers"),
		f.String("user-agent", "", "override protocol User-Agent; empty uses the profile/default"),
	}
}

func (f headerFlags) apply(base headers.Profile) (headers.Profile, error) {
	if *f.profilePath != "" {
		p, err := headers.Load(*f.profilePath)
		if err != nil {
			return p, err
		}
		base = p
	}
	if *f.userAgent != "" {
		base.UserAgent = *f.userAgent
	}
	return base, base.Validate()
}
