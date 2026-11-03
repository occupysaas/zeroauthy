package connrules

import (
	"context"
	"sort"

	"github.com/zeroauthy/zeroauthy/internal/phonenumber"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type PhoneConflict struct {
	UserIDs []string `json:"user_ids"`
	Reason  string   `json:"reason"`
}

// PhonePrecheck inspects existing values without rewriting any user data.
func PhonePrecheck(ctx context.Context, st store.Store, tid, connection string) ([]PhoneConflict, error) {
	if _, err := st.Phone().FindUsersByPhone(ctx, tid, connection, ""); err != nil {
		return nil, err
	}
	var out []PhoneConflict
	numbers := map[string][]string{}
	for offset := 0; ; offset += 100 {
		users, total, err := st.Users().List(ctx, tid, nil, store.UserSort{}, store.Page{Offset: offset, Limit: 100})
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			belongs := false
			for _, id := range u.Identities {
				if id.Connection == connection {
					belongs = true
					break
				}
			}
			if !belongs || u.PhoneNumber == "" {
				continue
			}
			n, e := phonenumber.NormalizeE164(u.PhoneNumber, "")
			if e != nil {
				out = append(out, PhoneConflict{UserIDs: []string{u.UserID}, Reason: "invalid"})
				continue
			}
			numbers[n] = append(numbers[n], u.UserID)
		}
		if offset+len(users) >= total || len(users) == 0 {
			break
		}
	}
	for _, ids := range numbers {
		if len(ids) > 1 {
			sort.Strings(ids)
			out = append(out, PhoneConflict{UserIDs: ids, Reason: "duplicate"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserIDs[0] < out[j].UserIDs[0] })
	return out, nil
}
