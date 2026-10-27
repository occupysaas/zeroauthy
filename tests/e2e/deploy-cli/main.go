package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	b, err := commandOutput(args)
	if len(b) > 0 {
		_, _ = os.Stdout.Write(append(b, '\n'))
	}
	return err
}
func commandOutput(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("expected compare, validate-manifest, exclusions or preflight-inventory")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	source := fs.String("source", "", "source export")
	target := fs.String("target", "", "target export")
	format := fs.String("format", "", "yaml or directory")
	manifestPath := fs.String("manifest", "manifest.json", "manifest file")
	registryPath := fs.String("registry", "", "registered handler snapshot")
	sourceDomain := fs.String("source-domain", "", "")
	targetDomain := fs.String("target-domain", "", "")
	input := fs.String("input", "", "API inventory JSON")
	credentials := fs.String("credentials", "", "private provider-secret map")
	output := fs.String("output", "", "private prepared connection JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, errors.New("unexpected positional arguments")
	}
	switch args[0] {
	case "prepare-federation":
		if *source == "" || *credentials == "" || *output == "" {
			return nil, errors.New("prepare-federation requires source, credentials and output")
		}
		e, err := load(*source, *format)
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(*credentials)
		if err != nil {
			return nil, errors.New("provider-secret injection file is unavailable")
		}
		var secrets map[string]string
		if json.Unmarshal(b, &secrets) != nil {
			return nil, errors.New("provider-secret injection file is invalid")
		}
		prepared, err := deploymigration.FederationImport(e, secrets)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(*output, prepared, 0600); err != nil {
			return nil, errors.New("private federation staging is unavailable")
		}
		return []byte(`{"prepared":true}`), nil
	case "compare":
		if *source == "" || *target == "" || (*format != "yaml" && *format != "directory") {
			return nil, errors.New("compare requires source, target and supported format")
		}
		s, err := load(*source, *format)
		if err != nil {
			return nil, err
		}
		d, err := load(*target, *format)
		if err != nil {
			return nil, err
		}
		m, err := LoadManifest(*manifestPath)
		if err != nil {
			return nil, err
		}
		r := Compare(s, d, m, Domains{*sourceDomain, *targetDomain})
		b, _ := json.Marshal(r)
		if !r.Equivalent {
			return b, errors.New("exports differ")
		}
		return b, nil
	case "validate-manifest":
		if *registryPath == "" {
			return nil, errors.New("registry snapshot required")
		}
		m, err := LoadManifest(*manifestPath)
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(*registryPath)
		if err != nil {
			return nil, errors.New("registry snapshot unavailable")
		}
		var names []string
		if json.Unmarshal(b, &names) != nil {
			return nil, errors.New("registry snapshot invalid")
		}
		if err := ValidateManifest(m, names); err != nil {
			return nil, err
		}
		return []byte(`{"valid":true}`), nil
	case "exclusions":
		m, err := LoadManifest(*manifestPath)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(Exclusions(m))
		return b, nil
	case "preflight-inventory":
		if *input == "" {
			return nil, errors.New("inventory input required")
		}
		b, err := os.ReadFile(*input)
		if err != nil {
			return nil, errors.New("inventory unavailable")
		}
		if err := PreflightInventory(b); err != nil {
			return nil, err
		}
		return []byte(`{"valid":true}`), nil
	default:
		return nil, errors.New("unknown deploy comparator command")
	}
}
func load(path, format string) (deploymigration.Export, error) {
	return deploymigration.LoadExport(path, format)
}
