package traffic

import (
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Snapshot struct {
	ID            string
	Username      string
	ClientIP      string
	UploadBytes   uint64
	DownloadBytes uint64
	UploadBPS     uint64
	DownloadBPS   uint64
	StartedAt     time.Time
}

type Tracker struct {
	mu       sync.Mutex
	sessions map[string]*sessionState
	totals   map[string]UserTotals
	lastRate map[string]UserTotals
	lastPoll time.Time
	nextID   atomic.Uint64
}

type UserTotals struct {
	UploadBytes   uint64
	DownloadBytes uint64
	UploadBPS     uint64
	DownloadBPS   uint64
	LastSeenAt    time.Time
	LastClientIP  string
}

type sessionState struct {
	username string
	clientIP string
	started  time.Time

	uploadBytes   atomic.Uint64
	downloadBytes atomic.Uint64

	lastSampleAt       time.Time
	lastUploadSample   uint64
	lastDownloadSample uint64
	lastSeenUnix       atomic.Int64
}

type Session struct {
	tracker *Tracker
	id      string
	once    sync.Once
}

func (s *Session) UploadBytes() uint64 {
	if s == nil || s.tracker == nil {
		return 0
	}
	s.tracker.mu.Lock()
	state := s.tracker.sessions[s.id]
	s.tracker.mu.Unlock()
	if state == nil {
		return 0
	}
	return state.uploadBytes.Load()
}

func (s *Session) DownloadBytes() uint64 {
	if s == nil || s.tracker == nil {
		return 0
	}
	s.tracker.mu.Lock()
	state := s.tracker.sessions[s.id]
	s.tracker.mu.Unlock()
	if state == nil {
		return 0
	}
	return state.downloadBytes.Load()
}

func NewTracker() *Tracker {
	return &Tracker{
		sessions: make(map[string]*sessionState),
		totals:   make(map[string]UserTotals),
		lastRate: make(map[string]UserTotals),
	}
}

func (t *Tracker) LoadPersistedTotals(store Store) error {
	if t == nil || store == nil {
		return nil
	}
	persisted, err := store.LoadTraffic()
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for username, totals := range persisted {
		t.totals[username] = totals
	}
	return nil
}

func (t *Tracker) ResetUserStats(username string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.totals[username] = UserTotals{}
}

func (t *Tracker) Start(username, clientIP string) *Session {
	if t == nil {
		return nil
	}
	if username == "" {
		username = "anonymous"
	}
	if clientIP == "" {
		clientIP = "unknown"
	}

	id := strconv.FormatUint(t.nextID.Add(1), 10)
	now := time.Now()

	t.mu.Lock()
	state := &sessionState{
		username:     username,
		clientIP:     clientIP,
		started:      now,
		lastSampleAt: now,
	}
	state.lastSeenUnix.Store(now.UnixNano())
	t.sessions[id] = state

	totals := t.totals[username]
	if totals.LastSeenAt.IsZero() || now.After(totals.LastSeenAt) {
		totals.LastSeenAt = now
		totals.LastClientIP = clientIP
	}
	t.totals[username] = totals
	t.mu.Unlock()

	return &Session{tracker: t, id: id}
}

func (s *Session) AddUpload(n int64) {
	if s == nil || n <= 0 || s.tracker == nil {
		return
	}
	s.tracker.mu.Lock()
	state := s.tracker.sessions[s.id]
	s.tracker.mu.Unlock()
	if state == nil {
		return
	}
	state.uploadBytes.Add(uint64(n))
	state.lastSeenUnix.Store(time.Now().UnixNano())
}

func (s *Session) AddDownload(n int64) {
	if s == nil || n <= 0 || s.tracker == nil {
		return
	}
	s.tracker.mu.Lock()
	state := s.tracker.sessions[s.id]
	s.tracker.mu.Unlock()
	if state == nil {
		return
	}
	state.downloadBytes.Add(uint64(n))
	state.lastSeenUnix.Store(time.Now().UnixNano())
}

func (s *Session) Close() {
	if s == nil || s.tracker == nil {
		return
	}
	s.once.Do(func() {
		s.tracker.mu.Lock()
		state := s.tracker.sessions[s.id]
		if state != nil {
			totals := s.tracker.totals[state.username]
			totals.UploadBytes += state.uploadBytes.Load()
			totals.DownloadBytes += state.downloadBytes.Load()
			lastSeenUnix := state.lastSeenUnix.Load()
			lastSeenAt := time.Unix(0, lastSeenUnix)
			if lastSeenUnix <= 0 {
				lastSeenAt = state.started
			}
			if totals.LastSeenAt.IsZero() || lastSeenAt.After(totals.LastSeenAt) {
				totals.LastSeenAt = lastSeenAt
				totals.LastClientIP = state.clientIP
			}
			s.tracker.totals[state.username] = totals
		}
		delete(s.tracker.sessions, s.id)
		s.tracker.mu.Unlock()
	})
}

func (t *Tracker) TotalsByUser() map[string]UserTotals {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()

	out := make(map[string]UserTotals, len(t.totals))
	for username, totals := range t.totals {
		out[username] = totals
	}

	for _, s := range t.sessions {
		totals := out[s.username]
		totals.UploadBytes += s.uploadBytes.Load()
		totals.DownloadBytes += s.downloadBytes.Load()
		lastSeenUnix := s.lastSeenUnix.Load()
		lastSeenAt := time.Unix(0, lastSeenUnix)
		if lastSeenUnix <= 0 {
			lastSeenAt = s.started
		}
		if totals.LastSeenAt.IsZero() || lastSeenAt.After(totals.LastSeenAt) {
			totals.LastSeenAt = lastSeenAt
			totals.LastClientIP = s.clientIP
		}
		out[s.username] = totals
	}

	elapsed := now.Sub(t.lastPoll)
	if elapsed <= 0 {
		elapsed = time.Second
	}

	nextLastRate := make(map[string]UserTotals, len(out))
	for username, totals := range out {
		prev := t.lastRate[username]

		if totals.UploadBytes >= prev.UploadBytes {
			totals.UploadBPS = uint64(float64(totals.UploadBytes-prev.UploadBytes) / elapsed.Seconds())
		}
		if totals.DownloadBytes >= prev.DownloadBytes {
			totals.DownloadBPS = uint64(float64(totals.DownloadBytes-prev.DownloadBytes) / elapsed.Seconds())
		}

		out[username] = totals
		nextLastRate[username] = UserTotals{
			UploadBytes:   totals.UploadBytes,
			DownloadBytes: totals.DownloadBytes,
		}
	}

	t.lastRate = nextLastRate
	t.lastPoll = now

	return out
}

func (t *Tracker) Snapshot() []Snapshot {
	if t == nil {
		return nil
	}

	now := time.Now()
	t.mu.Lock()
	out := make([]Snapshot, 0, len(t.sessions))
	for id, s := range t.sessions {
		upload := s.uploadBytes.Load()
		download := s.downloadBytes.Load()

		elapsed := now.Sub(s.lastSampleAt)
		if elapsed <= 0 {
			elapsed = time.Second
		}

		uploadDelta := upload - s.lastUploadSample
		downloadDelta := download - s.lastDownloadSample

		uploadBPS := uint64(float64(uploadDelta) / elapsed.Seconds())
		downloadBPS := uint64(float64(downloadDelta) / elapsed.Seconds())

		s.lastSampleAt = now
		s.lastUploadSample = upload
		s.lastDownloadSample = download

		out = append(out, Snapshot{
			ID:            id,
			Username:      s.username,
			ClientIP:      s.clientIP,
			UploadBytes:   upload,
			DownloadBytes: download,
			UploadBPS:     uploadBPS,
			DownloadBPS:   downloadBPS,
			StartedAt:     s.started,
		})
	}
	t.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Username == out[j].Username {
			return out[i].ClientIP < out[j].ClientIP
		}
		return out[i].Username < out[j].Username
	})

	return out
}
