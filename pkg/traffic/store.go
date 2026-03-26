package traffic

// Store persists per-user traffic totals across restarts.
type Store interface {
	LoadTraffic() (map[string]UserTotals, error)
	SaveTraffic(totals map[string]UserTotals) error
	ResetUserTraffic(username string) error
}
