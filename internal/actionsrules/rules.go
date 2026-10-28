package actionsrules

import (
	"fmt"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Runtime is the only supported Actions runtime.
const Runtime = "node22"

var (
	secretNameRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
	// npm names: optional @scope/, lowercase, no leading dot or underscore.
	packageNameRE = regexp.MustCompile(`^(@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$`)
	exactSemverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
)

func limit(name string) int { return Inventory().Limits[name] }

// NormalizeAction defaults the runtime and returns every rule a violates.
// The name is never trimmed or case-folded because names are case-sensitive.
func NormalizeAction(a *store.Action) []error {
	var errs []error
	if a.Runtime == "" {
		a.Runtime = Runtime
	}
	if a.Runtime != Runtime {
		errs = append(errs, fmt.Errorf("runtime must be %q", Runtime))
	}
	if n := utf8.RuneCountInString(a.Name); n < limit("name_min") || n > limit("name_max") || !utf8.ValidString(a.Name) {
		errs = append(errs, fmt.Errorf("name must be %d-%d characters", limit("name_min"), limit("name_max")))
	}
	if !knownTrigger(a.Trigger) {
		errs = append(errs, fmt.Errorf("unsupported trigger %q", a.Trigger))
	}
	if len(a.Code) > limit("code_bytes") {
		errs = append(errs, fmt.Errorf("code exceeds %d bytes", limit("code_bytes")))
	}
	errs = append(errs, ValidateDependencies(a.Dependencies)...)
	errs = append(errs, ValidateSecrets(a.Secrets)...)
	return errs
}

func knownTrigger(id string) bool {
	return slices.ContainsFunc(Inventory().Triggers, func(t TriggerContract) bool { return t.ID == id })
}

// ValidateDependencies refuses duplicates, bad package names and every
// version that is not exact semver, empty or "latest": ranges, tags, git,
// file, URL and tarball specs. Registry overrides are not representable in
// store.Dependency, so the transport layer must reject registry_url itself.
func ValidateDependencies(deps []store.Dependency) []error {
	var errs []error
	if len(deps) > limit("dependencies_max") {
		errs = append(errs, fmt.Errorf("at most %d dependencies", limit("dependencies_max")))
	}
	seen := map[string]bool{}
	for _, d := range deps {
		if len(d.Name) > 214 || !packageNameRE.MatchString(d.Name) {
			errs = append(errs, fmt.Errorf("invalid dependency name %q", d.Name))
		}
		if seen[d.Name] {
			errs = append(errs, fmt.Errorf("duplicate dependency %q", d.Name))
		}
		seen[d.Name] = true
		if d.Version != "" && d.Version != "latest" && !exactSemverRE.MatchString(d.Version) {
			errs = append(errs, fmt.Errorf("dependency %q version must be exact semver or latest", d.Name))
		}
	}
	return errs
}

// ValidateSecrets checks names and count. Values are sealed before they
// reach the store, so their size is enforced where they are still plaintext.
func ValidateSecrets(secrets []store.ActionSecret) []error {
	var errs []error
	if len(secrets) > limit("secrets_max") {
		errs = append(errs, fmt.Errorf("at most %d secrets", limit("secrets_max")))
	}
	seen := map[string]bool{}
	for _, s := range secrets {
		if !secretNameRE.MatchString(s.Name) {
			errs = append(errs, fmt.Errorf("invalid secret name %q", s.Name))
		}
		if seen[s.Name] {
			errs = append(errs, fmt.Errorf("duplicate secret %q", s.Name))
		}
		seen[s.Name] = true
	}
	return errs
}

// ValidateBindings checks the bindings of one trigger.
func ValidateBindings(trigger string, b []store.Binding) []error {
	var errs []error
	if !knownTrigger(trigger) {
		errs = append(errs, fmt.Errorf("unsupported trigger %q", trigger))
	}
	if len(b) > limit("bindings_per_trigger_max") {
		errs = append(errs, fmt.Errorf("at most %d bindings per trigger", limit("bindings_per_trigger_max")))
	}
	for i, v := range b {
		if v.ActionID == "" {
			errs = append(errs, fmt.Errorf("binding %d has no action", i))
		}
		if v.Trigger != "" && v.Trigger != trigger {
			errs = append(errs, fmt.Errorf("binding %d trigger %q does not match %q", i, v.Trigger, trigger))
		}
	}
	return errs
}
