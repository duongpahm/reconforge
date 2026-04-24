package api

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/reconforge/reconforge/internal/models"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type scanWSEvent struct {
	Type      string      `json:"type"`
	ScanID    uint        `json:"scan_id"`
	Status    string      `json:"status"`
	Target    string      `json:"target,omitempty"`
	Mode      string      `json:"mode,omitempty"`
	Findings  int         `json:"findings"`
	Duration  string      `json:"duration,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	Payload   interface{} `json:"payload,omitempty"`
}

func (s *Server) handleScanWS(c *gin.Context) {
	scanID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || scanID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan id"})
		return
	}

	if !isWebSocketRequest(c.Request) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "websocket upgrade required"})
		return
	}

	key := strings.TrimSpace(c.GetHeader("Sec-WebSocket-Key"))
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing websocket key"})
		return
	}

	conn, rw, err := upgradeWebSocket(c.Writer, c.Request, key)
	if err != nil {
		s.logger.Warn().Err(err).Uint64("scan_id", scanID).Msg("websocket upgrade failed")
		return
	}
	defer conn.Close()

	ctx := c.Request.Context()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastStatus := ""
	for {
		scan, err := s.lookupScan(uint(scanID))
		if err != nil {
			_ = writeWebSocketJSON(rw, scanWSEvent{
				Type:      "error",
				ScanID:    uint(scanID),
				Status:    "unknown",
				Timestamp: time.Now().UTC(),
				Payload:   map[string]string{"error": "scan not found"},
			})
			return
		}

		eventType := "scan_update"
		if lastStatus == "" {
			eventType = "scan_snapshot"
		} else if lastStatus != scan.Status {
			eventType = "status_change"
		}
		lastStatus = scan.Status

		if err := writeWebSocketJSON(rw, scanToWSEvent(eventType, scan)); err != nil {
			s.logger.Debug().Err(err).Uint("scan_id", scan.ID).Msg("websocket client disconnected")
			return
		}
		if isTerminalScanStatus(scan.Status) {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) lookupScan(id uint) (*models.Scan, error) {
	var scan models.Scan
	if err := s.db.First(&scan, id).Error; err != nil {
		return nil, err
	}
	return &scan, nil
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerContainsToken(r.Header.Get("Connection"), "upgrade")
}

func headerContainsToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func upgradeWebSocket(w http.ResponseWriter, r *http.Request, key string) (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket hijacking unsupported", http.StatusInternalServerError)
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}

	acceptHash := sha1.Sum([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(acceptHash[:])
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(response); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

func writeWebSocketJSON(rw *bufio.ReadWriter, event scanWSEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := writeWebSocketTextFrame(rw, payload); err != nil {
		return err
	}
	return rw.Flush()
}

func writeWebSocketTextFrame(rw *bufio.ReadWriter, payload []byte) error {
	if err := rw.WriteByte(0x81); err != nil {
		return err
	}

	size := len(payload)
	switch {
	case size < 126:
		if err := rw.WriteByte(byte(size)); err != nil {
			return err
		}
	case size <= 65535:
		if err := rw.WriteByte(126); err != nil {
			return err
		}
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(size))
		if _, err := rw.Write(b[:]); err != nil {
			return err
		}
	default:
		if err := rw.WriteByte(127); err != nil {
			return err
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(size))
		if _, err := rw.Write(b[:]); err != nil {
			return err
		}
	}

	_, err := rw.Write(payload)
	return err
}

func scanToWSEvent(eventType string, scan *models.Scan) scanWSEvent {
	return scanWSEvent{
		Type:      eventType,
		ScanID:    scan.ID,
		Status:    scan.Status,
		Target:    scan.TargetName,
		Mode:      scan.Mode,
		Findings:  scan.Findings,
		Duration:  scan.Duration.String(),
		Timestamp: time.Now().UTC(),
	}
}

func isTerminalScanStatus(status string) bool {
	switch strings.ToLower(status) {
	case "completed", "complete", "failed", "cancelled", "canceled":
		return true
	default:
		return false
	}
}
