package seed

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

func preserveOmittedTenant(dst, before *store.Tenant, supplied map[string]any) {
	if supplied == nil {
		return
	} // programmatic legacy seeds define the complete old shape
	fields := map[string]string{"friendly_name": "FriendlyName", "domains": "Domains", "default_audience": "DefaultAudience", "default_directory": "DefaultDirectory", "allowed_logout_urls": "AllowedLogoutURLs", "enabled_locales": "EnabledLocales", "custom_text": "CustomText", "session_lifetime": "SessionLifetime", "idle_session_lifetime": "IdleSessionLifetime", "skip_non_verifiable_callback_uri_confirmation_prompt": "SkipNonVerifiableCallbackURIConfirmationPrompt", "use_scope_descriptions_for_consent": "UseScopeDescriptionsForConsent", "pushed_authorization_requests_supported": "PushedAuthorizationRequestsSupported"}
	d, b := reflect.ValueOf(dst).Elem(), reflect.ValueOf(before).Elem()
	for key, field := range fields {
		if _, ok := supplied[key]; !ok {
			d.FieldByName(field).Set(b.FieldByName(field))
		}
	}
	branding, _ := supplied["branding"].(map[string]any)
	if _, ok := branding["logo_url"]; !ok {
		dst.Branding.LogoURL = before.Branding.LogoURL
	}
	if _, ok := branding["primary_color"]; !ok {
		dst.Branding.PrimaryColor = before.Branding.PrimaryColor
	}
	device, _ := supplied["device_flow"].(map[string]any)
	if _, ok := device["charset"]; !ok {
		dst.DeviceFlowCharset = before.DeviceFlowCharset
	}
	if _, ok := device["mask"]; !ok {
		dst.DeviceFlowMask = before.DeviceFlowMask
	}
}

func applyTenantSettings(tn *store.Tenant, in Tenant, w keys.Wrapper) error {
	if branding, ok := in.supplied["branding"].(map[string]any); ok {
		if _, present := branding["logo_url"]; present {
			tn.PictureURL = tn.Branding.LogoURL
		}
	}
	if in.Settings != nil {
		out, err := tenantrules.Apply(tn, in.Settings)
		if err != nil {
			return err
		}
		*tn = *out
	}
	if len(in.AttackProtection) == 0 {
		return nil
	}
	policy := tn.ProtectionSettings
	if !tn.ProtectionSettingsInitialized {
		policy = protectionrules.Defaults()
	}
	for feature, patch := range in.AttackProtection {
		var err error
		if feature == "captcha" {
			policy, err = keys.PatchCAPTCHA(w, tn.ID, policy, patch)
		} else {
			policy, err = protectionrules.Apply(policy, feature, patch)
		}
		if err != nil {
			return err
		}
	}
	tn.ProtectionSettings = policy
	tn.ProtectionSettingsInitialized = true
	return nil
}

// InitializeProtection performs the once-only legacy transition after seed/system
// provisioning. The persisted marker protects API edits across restarts.
func InitializeProtection(ctx context.Context, st store.Store, cfg config.Security, log *slog.Logger) error {
	var initialized []string
	legacy := cfg.LoginMaxAttemptsExplicit || cfg.LoginLockoutSecondsExplicit
	err := st.WithTx(ctx, func(tx store.Store) error {
		tenants, err := tx.Tenants().List(ctx)
		if err != nil {
			return err
		}
		for _, tn := range tenants {
			if tn.ProtectionSettingsInitialized {
				continue
			}
			tn.ProtectionSettings = protectionrules.Defaults()
			if legacy {
				tn.ProtectionSettings.BruteForce.MaxAttempts = cfg.LoginMaxAttempts
				tn.ProtectionSettings.LegacyLockoutSeconds = cfg.LoginLockoutSeconds
				tn.ProtectionSettings.LegacyIPMaxAttempts = 10 * cfg.LoginMaxAttempts
			}
			tn.ProtectionSettingsInitialized = true
			if err := tx.Tenants().Update(ctx, tn); err != nil {
				return err
			}
			initialized = append(initialized, tn.ID)
		}
		return nil
	})
	if err == nil && log != nil {
		for _, id := range initialized {
			if legacy {
				log.Warn("tenant protection policy initialized in legacy compatibility mode", "tenant_id", id)
			} else {
				log.Info("tenant protection policy initialized", "tenant_id", id, "legacy_compatibility", false)
			}
		}
	}
	return err
}

func validateTenantSettings(in *Tenant) error {
	for key, value := range in.Settings {
		legacy := strings.TrimSuffix(key, "_in_minutes")
		_, duplicate := in.supplied[legacy]
		if key == "picture_url" {
			branding, _ := in.supplied["branding"].(map[string]any)
			_, duplicate = branding["logo_url"]
		}
		if key == "device_flow" && duplicate && value != nil {
			old, _ := in.supplied["device_flow"].(map[string]any)
			patch, _ := value.(map[string]any)
			duplicate = false
			for child := range patch {
				if _, ok := old[child]; ok {
					duplicate = true
				}
			}
		}
		if duplicate {
			return fmt.Errorf("seed: setting %s is supplied both at tenant level and in settings", key)
		}
	}

	if _, ok := in.supplied["settings"]; ok && in.Settings == nil {
		return fmt.Errorf("seed: settings must be an object")
	}
	if _, ok := in.supplied["attack_protection"]; ok && in.AttackProtection == nil {
		return fmt.Errorf("seed: attack_protection must be an object")
	}
	if in.Settings != nil {
		if _, err := tenantrules.Apply(&store.Tenant{}, in.Settings); err != nil {
			return err
		}
	}
	policy := protectionrules.Defaults()
	for feature, patch := range in.AttackProtection {
		var err error
		policy, err = protectionrules.Apply(policy, feature, patch)
		if err != nil {
			return err
		}
	}
	return nil
}
