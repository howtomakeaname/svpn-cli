package main

import "flag"

// application holds per-invocation CLI behavior, separate from protocol state.
type application struct{}

func (a *application) newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

func (a *application) parseFlags(f *flag.FlagSet, args []string) error {
	return f.Parse(args)
}
