package grpcstore

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	pb "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

func quotaToPB(v *store.TokenQuota) *pb.TokenQuotaMsg {
	if v == nil {
		return nil
	}
	return &pb.TokenQuotaMsg{
		Enforce: v.Enforce,
		PerHour: int64(v.PerHour),
		PerDay:  int64(v.PerDay),
	}
}

func quotaFromPB(v *pb.TokenQuotaMsg) *store.TokenQuota {
	if v == nil {
		return nil
	}
	return &store.TokenQuota{
		Enforce: v.Enforce,
		PerHour: int(v.PerHour),
		PerDay:  int(v.PerDay),
	}
}

func defaultQuotaToPB(v *store.DefaultTokenQuota) *pb.DefaultQuotaMsg {
	if v == nil {
		return nil
	}
	return &pb.DefaultQuotaMsg{
		Clients:       quotaToPB(v.Clients),
		Organizations: quotaToPB(v.Organizations),
	}
}

func defaultQuotaFromPB(v *pb.DefaultQuotaMsg) *store.DefaultTokenQuota {
	if v == nil {
		return nil
	}
	return &store.DefaultTokenQuota{
		Clients:       quotaFromPB(v.Clients),
		Organizations: quotaFromPB(v.Organizations),
	}
}

func popToPB(v *store.ProofOfPossession) *pb.PoPConfig {
	if v == nil {
		return nil
	}
	return &pb.PoPConfig{
		Mechanism:   v.Mechanism,
		Required:    v.Required,
		RequiredFor: v.RequiredFor,
	}
}

func popFromPB(v *pb.PoPConfig) *store.ProofOfPossession {
	if v == nil {
		return nil
	}
	return &store.ProofOfPossession{
		Mechanism:   v.Mechanism,
		Required:    v.Required,
		RequiredFor: v.RequiredFor,
	}
}

func deviceToPB(v *store.RefreshTokenDevice) *pb.RefreshDeviceMsg {
	if v == nil {
		return nil
	}
	return &pb.RefreshDeviceMsg{
		InitialIp:        v.InitialIP,
		InitialAsn:       v.InitialASN,
		InitialUserAgent: v.InitialUserAgent,
		LastIp:           v.LastIP,
		LastAsn:          v.LastASN,
		LastUserAgent:    v.LastUserAgent,
	}
}

func deviceFromPB(v *pb.RefreshDeviceMsg) *store.RefreshTokenDevice {
	if v == nil {
		return nil
	}
	return &store.RefreshTokenDevice{
		InitialIP:        v.InitialIp,
		InitialASN:       v.InitialAsn,
		InitialUserAgent: v.InitialUserAgent,
		LastIP:           v.LastIp,
		LastASN:          v.LastAsn,
		LastUserAgent:    v.LastUserAgent,
	}
}

func policiesToPB(v []store.MRRTPolicy) *pb.MRRTPolicyList {
	if v == nil {
		return nil
	}
	out := &pb.MRRTPolicyList{}
	for _, p := range v {
		out.Values = append(out.Values, &pb.MRRTPolicyMsg{Audience: p.Audience, Scope: stringsToPB(p.Scope)})
	}
	return out
}

func policiesFromPB(v *pb.MRRTPolicyList) []store.MRRTPolicy {
	if v == nil {
		return nil
	}
	out := make([]store.MRRTPolicy, 0, len(v.Values))
	for _, p := range v.Values {
		out = append(out, store.MRRTPolicy{Audience: p.GetAudience(), Scope: stringsFromPB(p.GetScope())})
	}
	return out
}
