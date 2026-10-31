package mgmt

import (
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// dailyStatsWindow validates calendar bounds before any date iteration. Comparing
// dates directly avoids duration saturation for ranges spanning many centuries.
func dailyStatsWindow(r *http.Request, now time.Time) (time.Time, time.Time, error) {
	now = now.UTC()
	to := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	from := to.AddDate(0, 0, 1-logLimits["stats_default_days"])
	for key, values := range r.URL.Query() {
		if (key != "from" && key != "to") || len(values) != 1 {
			return from, to, badQuery("Unsupported or repeated parameter %q", key)
		}
		if len(values[0]) != 8 {
			return from, to, badQuery("Invalid %s", key)
		}
		day, err := time.Parse("20060102", values[0])
		if err != nil {
			return from, to, badQuery("Invalid %s", key)
		}
		if key == "from" {
			from = day
		} else {
			to = day
		}
	}
	if store.ValidateLogTimes(from, to) != nil || from.After(to) || to.After(from.AddDate(0, 0, logLimits["stats_max_days"]-1)) {
		return from, to, badQuery("Invalid daily stats range")
	}
	return from, to, nil
}

type dailyStatView struct {
	Date            string `json:"date"`
	Logins          int    `json:"logins"`
	Signups         int    `json:"signups"`
	LeakedPasswords int    `json:"leaked_passwords"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// GetDailyStats returns every inclusive UTC day, including missing days with
// zero counters and deterministic midnight timestamps (D-0057's local rule).
func (h *Handlers) GetDailyStats(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	from, to, err := dailyStatsWindow(r, h.now())
	if err != nil {
		Fail(w, err)
		return
	}
	rows, err := repo.DailyStats(r.Context(), resolved(r).ID, from, to)
	if err != nil {
		h.logError(w, r, err)
		return
	}
	byDay := make(map[string]store.DailyStat, len(rows))
	for _, row := range rows {
		byDay[row.Day.UTC().Format("20060102")] = row
	}
	out := make([]dailyStatView, 0, logLimits["stats_max_days"])
	for day := from; !day.After(to); day = day.AddDate(0, 0, 1) {
		row, found := byDay[day.Format("20060102")]
		if !found {
			row = store.DailyStat{CreatedAt: day, UpdatedAt: day}
		}
		out = append(out, dailyStatView{
			Date: day.Format(time.RFC3339), Logins: row.Logins,
			Signups: row.Signups, LeakedPasswords: row.LeakedPasswords,
			CreatedAt: row.CreatedAt.UTC().Format(time.RFC3339Nano),
			UpdatedAt: row.UpdatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// GetActiveUsers counts existing users whose successful last login is at least
// now minus thirty days; the store provides the inclusive lower bound.
func (h *Handlers) GetActiveUsers(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.logsRepo(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		Fail(w, badQuery("Unsupported query parameters"))
		return
	}
	n, err := repo.ActiveUsers(r.Context(), resolved(r).ID, h.now().Add(-30*24*time.Hour))
	if err != nil {
		h.logError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, n)
}
