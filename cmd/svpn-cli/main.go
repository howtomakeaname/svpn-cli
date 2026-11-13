package main

import (
    "errors"
    "flag"
    "fmt"
    "os"
)

func run(args []string) error {
    if len(args)>0 && args[0]=="auth" {return runAuth(args[1:])}
    return errors.New("usage: svpn-cli auth init|sso|finish|exchange|status")
}

func main() {
    if err:=run(os.Args[1:]);err!=nil && !errors.Is(err,flag.ErrHelp) {
        fmt.Fprintln(os.Stderr,"svpn-cli:",err)
        os.Exit(1)
    }
}
