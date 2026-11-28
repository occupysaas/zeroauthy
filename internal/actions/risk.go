package actions

import (
	"context"
	"net/http"
)

// RiskInput contains local signals only; we do not infer location or bots.
type RiskInput struct{ KnownDevice, BlockedIP bool }
type Assessment struct {
	Code       string         `json:"code"`
	Confidence string         `json:"confidence"`
	Details    map[string]any `json:"details,omitempty"`
}
type RiskAssessment struct {
	Confidence  string                `json:"confidence"`
	Assessments map[string]Assessment `json:"assessments"`
}

func AssessRisk(in RiskInput) RiskAssessment {
	device := Assessment{Code: "unknown_device", Confidence: "low"}
	if in.KnownDevice {
		device = Assessment{Code: "match", Confidence: "high"}
	}
	ip := Assessment{Code: "not_found_on_deny_list", Confidence: "high"}
	if in.BlockedIP {
		ip = Assessment{Code: "found_on_deny_list", Confidence: "low"}
	}
	confidence := "high"
	if device.Confidence == "low" || ip.Confidence == "low" {
		confidence = "low"
	}
	return RiskAssessment{Confidence: confidence, Assessments: map[string]Assessment{"NewDevice": device, "UntrustedIP": ip, "ImpossibleTravel": {Code: "missing_geoip", Confidence: "neutral"}, "AgentDetection": {Code: "unknown", Confidence: "neutral"}}}
}

// SecurityContext reads only operator-selected headers. The terminating proxy
// must overwrite these headers; empty configuration trusts no fingerprint.
func SecurityContext(r *http.Request, ja3Header, ja4Header string) map[string]any {
	out := map[string]any{"ja3": nil, "ja4": nil}
	for key, header := range map[string]string{"ja3": ja3Header, "ja4": ja4Header} {
		if header == "" {
			continue
		}
		v := r.Header.Get(header)
		if len(v) > 1024 {
			continue
		}
		valid := v != ""
		for i := 0; i < len(v); i++ {
			if v[i] < 0x21 || v[i] > 0x7e {
				valid = false
				break
			}
		}
		if valid {
			out[key] = v
		}
	}
	return out
}

type securityContextKey struct{}

func WithSecurityContext(ctx context.Context, v map[string]any) context.Context {
	return context.WithValue(ctx, securityContextKey{}, v)
}
func SecurityContextFrom(ctx context.Context) map[string]any {
	v, _ := ctx.Value(securityContextKey{}).(map[string]any)
	return v
}

// CorrelationID accepts a bounded, printable request correlation identifier.
func CorrelationID(r *http.Request) string {
	v := r.Header.Get("X-Correlation-ID")
	if len(v) > 64 {
		return ""
	}
	for i := range len(v) {
		if v[i] < 0x21 || v[i] > 0x7e {
			return ""
		}
	}
	return v
}
