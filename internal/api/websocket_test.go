package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/models"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestHandleScanWSRejectsNonUpgradeRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := newTestDB(t)
	srv := NewServer(&config.Config{}, zerolog.Nop(), db, nil)

	req := httptest.NewRequest(http.MethodGet, "/ws/scans/1", nil)
	rec := httptest.NewRecorder()

	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "websocket upgrade required")
}

func TestScanToWSEvent(t *testing.T) {
	scan := &models.Scan{
		Model:      gorm.Model{ID: 42},
		TargetName: "example.com",
		Mode:       "recon",
		Status:     "running",
		Findings:   7,
		Duration:   3 * time.Second,
	}

	event := scanToWSEvent("scan_snapshot", scan)

	assert.Equal(t, "scan_snapshot", event.Type)
	assert.Equal(t, uint(42), event.ScanID)
	assert.Equal(t, "running", event.Status)
	assert.Equal(t, "example.com", event.Target)
	assert.Equal(t, "recon", event.Mode)
	assert.Equal(t, 7, event.Findings)
	assert.Equal(t, "3s", event.Duration)
	assert.False(t, event.Timestamp.IsZero())
}

func TestWebSocketHeaderHelpers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/scans/1", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "keep-alive, Upgrade")

	assert.True(t, isWebSocketRequest(req))
	assert.True(t, headerContainsToken("keep-alive, Upgrade", "upgrade"))
	assert.False(t, isTerminalScanStatus("running"))
	assert.True(t, isTerminalScanStatus("completed"))
	assert.True(t, isTerminalScanStatus("failed"))
}

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Target{}, &models.Scan{}))
	return db
}
