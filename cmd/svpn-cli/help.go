package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

type commandSpec struct {
	Name     string   `json:"name"`
	Summary  string   `json:"summary"`
	Usage    string   `json:"usage"`
	Effects  []string `json:"effects"`
	Examples []string `json:"examples,omitempty"`
}

// These descriptions are shared by text help and JSON discovery. Flag names,
// defaults and types are read directly from the command's real FlagSet.
var commandSpecs = []commandSpec{
	{"auth init", "Discover an organization and register a device; reuse an existing MID.", "auth init --pin PIN [--state FILE] [--machine NAME]", []string{"network", "device_registration", "write_private_state"}, []string{"svpn-cli --json auth init --pin YOUR_ORGANIZATION_PIN --state private/auth.json --machine My-Device"}},
	{"auth sso", "Create a browser SSO/MFA login URL, or list domain choices in an error.", "auth sso [--state FILE] [--domain ID]", []string{"network", "replace_pending_sso", "human_browser_login"}, nil},
	{"auth finish", "Import a single-use HTTPS SSO callback without printing credentials.", "auth finish [--state FILE] [--callback-file FILE | --callback-stdin]", []string{"network", "consume_sso_callback", "write_private_state"}, []string{"svpn-cli --json auth finish --state private/auth.json --callback-file private/callback.txt"}},
	{"auth exchange", "Exchange the saved device login ticket.", "auth exchange [--state FILE]", []string{"network", "write_private_state"}, nil},
	{"auth inspect", "Read a redacted local login summary and next action; no network request.", "auth inspect [--state FILE]", []string{"read_private_state"}, []string{"svpn-cli --json auth inspect --state private/auth.json"}},
	{"auth status", "Request the server's ticket-status response and save it privately.", "auth status [--state FILE]", []string{"network", "write_private_state"}, nil},
	{"policy", "Save an authorized resource/device policy response privately.", "policy [--state FILE] [--output FILE] [--host]", []string{"network", "write_private_policy"}, nil},
	{"ticket", "Diagnostic: request a resource ticket using an issued policy area.", "ticket --target HOST:PORT --area ID [--set-id ID] [--state FILE] [--output FILE]", []string{"network", "issue_ticket", "write_private_ticket"}, nil},
	{"check", "Validate a private session file locally; does not test connectivity.", "check --session FILE", []string{"read_private_session"}, nil},
	{"connect", "Relay raw TCP on stdin/stdout, suitable for SSH ProxyCommand.", "connect (--state FILE | --session FILE) [OPTIONS] HOST PORT", []string{"network", "issue_ticket", "raw_tcp_stream"}, []string{"ssh -o 'ProxyCommand=svpn-cli connect --state /absolute/path/private/auth.json %h %p' user@ssh.internal.example"}},
	{"serve", "Run loopback HTTP/SOCKS5 TCP proxies; JSON emits ready/stopped events.", "serve (--state FILE | --session FILE) [--mode vpn-only|auto] [OPTIONS]", []string{"network", "issue_ticket", "listen_loopback", "long_running"}, []string{"svpn-cli --json serve --state private/auth.json --mode auto --http 127.0.0.1:0 --socks ''"}},
	{"forward", "Forward a local loopback TCP port to an authorized remote endpoint.", "forward (--state FILE | --session FILE) --target HOST:PORT [--listen IP:PORT] [OPTIONS]", []string{"network", "issue_ticket", "listen_loopback", "long_running"}, []string{"svpn-cli --json forward --state private/auth.json --listen 127.0.0.1:8888 --target notebook.internal.example:8888"}},
	{"version", "Show build version, commit, platform and date.", "version", []string{}, nil},
}

func commandName(args []string) string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "help"
	}
	name := args[0]
	if name == "auth" && len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		name += " " + args[1]
	}
	if name == "auth" || name == "help" {
		return name
	}
	for _, spec := range commandSpecs {
		if spec.Name == name {
			return name
		}
	}
	return "unknown"
}

func (a *application) newFlagSet(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	// Parse diagnostics may echo arbitrary flag values. We report safe structured
	// errors ourselves, and render requested help on stdout.
	f.SetOutput(io.Discard)
	f.BoolVar(&a.json, "json", a.json, "versioned JSON results; implies no interactive prompts (connect stdout stays raw TCP)")
	f.BoolVar(&a.nonInteractive, "non-interactive", a.nonInteractive, "never prompt; auth finish requires an explicit callback input")
	f.Lookup("json").DefValue = "false"
	f.Lookup("non-interactive").DefValue = "false"
	f.Usage = func() {}
	return f
}

func (a *application) parseFlags(f *flag.FlagSet, args []string) error {
	err := f.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		if err := a.showHelp(f); err != nil {
			return err
		}
		return flag.ErrHelp
	}
	if err != nil {
		return usageError("Invalid command options; use svpn-cli help COMMAND for accepted flags and value types.")
	}
	return nil
}

func (a *application) showHelp(f *flag.FlagSet) error {
	name := f.Name()
	if name == "" || name == "auth" {
		commands := make([]commandSpec, 0, len(commandSpecs))
		for _, spec := range commandSpecs {
			if name == "" || strings.HasPrefix(spec.Name, "auth ") {
				commands = append(commands, spec)
			}
		}
		if a.json {
			return a.result("help", "", map[string]any{"commands": commands, "global_flags": helpFlags(f), "discovery": "svpn-cli --json help COMMAND [SUBCOMMAND]", "exit_codes": map[string]int{"success": 0, "operation_failed": 1, "invalid_argument": 2, "authentication_or_interaction_required": 3, "local_file_error": 4, "remote_request_failed": 5}})
		}
		fmt.Fprintln(a.out, "svpn-cli: experimental iOA / SVPN TCP client\n\nUsage: svpn-cli [--json] [--non-interactive] COMMAND [OPTIONS]")
		for _, spec := range commands {
			fmt.Fprintf(a.out, "  %-15s %s\n", spec.Name, spec.Summary)
		}
		fmt.Fprintln(a.out, "\nUse 'svpn-cli help COMMAND [SUBCOMMAND]' for flags and examples.\nPut options before positional HOST PORT. Use -- before literal positional values.\n--json produces versioned results and safe errors; connect stdout always stays raw TCP.\nserve --json emits NDJSON ready/stopped events; keep it running under a supervisor.\nLogin: auth init -> auth sso -> human browser login/MFA -> auth finish -> auth exchange.\nInspect progress with auth inspect; credentials remain in private files.\nserve: vpn-only for upstream routing; auto uses policy and sends unmatched traffic directly.\nProtected destinations fail closed. See docs/automation.md for the agent contract.")
		return nil
	}
	var spec commandSpec
	for _, candidate := range commandSpecs {
		if candidate.Name == name {
			spec = candidate
		}
	}
	if a.json {
		return a.result("help", "", map[string]any{"command": spec, "flags": helpFlags(f), "options_before_positionals": true})
	}
	fmt.Fprintf(a.out, "%s\n\nUsage: svpn-cli %s\n\nOptions:\n", spec.Summary, spec.Usage)
	for _, option := range helpFlags(f) {
		fmt.Fprintf(a.out, "  --%-20s %s (type: %s; default: %q)\n", option.Name, option.Description, option.Type, option.Default)
	}
	for _, example := range spec.Examples {
		fmt.Fprintf(a.out, "\nExample: %s\n", example)
	}
	return nil
}

type flagHelp struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Default     string `json:"default"`
	Description string `json:"description"`
}

func helpFlags(f *flag.FlagSet) []flagHelp {
	options := make([]flagHelp, 0)
	f.VisitAll(func(option *flag.Flag) {
		kind := "string"
		if getter, ok := option.Value.(flag.Getter); ok {
			switch getter.Get().(type) {
			case bool:
				kind = "boolean"
			case int:
				kind = "integer"
			}
		}
		options = append(options, flagHelp{option.Name, kind, option.DefValue, option.Usage})
	})
	return options
}
