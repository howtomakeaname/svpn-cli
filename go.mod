module github.com/howtomakeaname/svpn-cli

go 1.27.3

require (
	gitee.com/Trisia/gotlcp v1.6.2
	github.com/emmansun/gmsm v0.45.0
	golang.org/x/crypto v0.59.0
	golang.org/x/sys v0.50.0
	golang.org/x/term v0.48.0
	gvisor.dev/gvisor v0.0.0-20261113141358-019ce5abd766
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace gitee.com/Trisia/gotlcp => github.com/howtomakeaname/gotlcp v1.6.3-0.20261113152007-97f5c590be74
