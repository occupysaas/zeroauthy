package events

import "crypto/rand"

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randomID(prefix string) string {
	var out [22]byte
	for i := 0; i < len(out); {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("events: crypto/rand unavailable")
		}
		for _, v := range b {
			if v >= 248 {
				continue
			}
			out[i] = alphabet[int(v)%len(alphabet)]
			i++
			if i == len(out) {
				break
			}
		}
	}
	return prefix + string(out[:])
}
func NewEventID() string  { return randomID("evt_") }
func NewStreamID() string { return randomID("est_") }
