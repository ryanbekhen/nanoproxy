package traffic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTracker_SessionLifecycleAndSnapshot(t *testing.T) {
	tracker := NewTracker()
	s := tracker.Start("alice", "10.0.0.2")
	s.AddUpload(100)
	s.AddDownload(200)

	first := tracker.Snapshot()
	assert.Len(t, first, 1)
	assert.Equal(t, "alice", first[0].Username)
	assert.Equal(t, "10.0.0.2", first[0].ClientIP)
	assert.Equal(t, uint64(100), first[0].UploadBytes)
	assert.Equal(t, uint64(200), first[0].DownloadBytes)

	time.Sleep(20 * time.Millisecond)
	s.AddUpload(50)
	s.AddDownload(30)
	second := tracker.Snapshot()
	assert.Len(t, second, 1)
	assert.Equal(t, uint64(150), second[0].UploadBytes)
	assert.Equal(t, uint64(230), second[0].DownloadBytes)
	assert.GreaterOrEqual(t, second[0].UploadBPS, uint64(1))
	assert.GreaterOrEqual(t, second[0].DownloadBPS, uint64(1))

	s.Close()
	assert.Empty(t, tracker.Snapshot())
}

func TestTracker_DefaultLabels(t *testing.T) {
	tracker := NewTracker()
	_ = tracker.Start("", "")
	snaps := tracker.Snapshot()
	assert.Len(t, snaps, 1)
	assert.Equal(t, "anonymous", snaps[0].Username)
	assert.Equal(t, "unknown", snaps[0].ClientIP)
}

func TestTracker_TotalsByUser_PersistsAfterSessionClose(t *testing.T) {
	tracker := NewTracker()
	s1 := tracker.Start("alice", "10.0.0.2")
	s1.AddUpload(120)
	s1.AddDownload(300)

	totals := tracker.TotalsByUser()
	assert.Equal(t, uint64(120), totals["alice"].UploadBytes)
	assert.Equal(t, uint64(300), totals["alice"].DownloadBytes)
	assert.False(t, totals["alice"].LastSeenAt.IsZero())
	assert.Equal(t, "10.0.0.2", totals["alice"].LastClientIP)

	s1.Close()
	totals = tracker.TotalsByUser()
	assert.Equal(t, uint64(120), totals["alice"].UploadBytes)
	assert.Equal(t, uint64(300), totals["alice"].DownloadBytes)
	assert.False(t, totals["alice"].LastSeenAt.IsZero())

	s2 := tracker.Start("alice", "10.0.0.3")
	s2.AddUpload(30)
	s2.AddDownload(50)
	totals = tracker.TotalsByUser()
	assert.Equal(t, uint64(150), totals["alice"].UploadBytes)
	assert.Equal(t, uint64(350), totals["alice"].DownloadBytes)
	assert.Equal(t, "10.0.0.3", totals["alice"].LastClientIP)
}

func TestTracker_TotalsByUser_ComputesRateAcrossPolls(t *testing.T) {
	tracker := NewTracker()

	// Prime the rate baseline.
	_ = tracker.TotalsByUser()

	s := tracker.Start("alice", "10.0.0.2")
	s.AddUpload(1024)
	s.AddDownload(2048)
	s.Close()

	time.Sleep(20 * time.Millisecond)
	totals := tracker.TotalsByUser()

	assert.Equal(t, uint64(1024), totals["alice"].UploadBytes)
	assert.Equal(t, uint64(2048), totals["alice"].DownloadBytes)
	assert.Greater(t, totals["alice"].UploadBPS, uint64(0))
	assert.Greater(t, totals["alice"].DownloadBPS, uint64(0))
}
