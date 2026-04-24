package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/models"
	"github.com/reconforge/reconforge/internal/temporal"
	"github.com/rs/zerolog"
	"go.temporal.io/sdk/client"
	"gorm.io/gorm"
)

// Server represents the REST API server.
type Server struct {
	router     *gin.Engine
	cfg        *config.Config
	logger     zerolog.Logger
	db         *gorm.DB
	tempClient client.Client
}

// NewServer initializes the API server with routes.
func NewServer(cfg *config.Config, logger zerolog.Logger, db *gorm.DB, tempClient client.Client) *Server {
	// Set Gin mode based on zerolog level
	if logger.GetLevel() == zerolog.DebugLevel {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())

	// Simple logging middleware
	r.Use(func(c *gin.Context) {
		logger.Info().Str("method", c.Request.Method).Str("path", c.Request.URL.Path).Msg("API request")
		c.Next()
	})

	s := &Server{
		router:     r,
		cfg:        cfg,
		logger:     logger,
		db:         db,
		tempClient: tempClient,
	}

	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	v1 := s.router.Group("/api/v1")
	{
		v1.GET("/health", s.handleHealth)
		v1.POST("/scans", s.handleStartScan)
		v1.GET("/scans", s.handleListScans)
	}

	// WebSocket endpoint
	s.router.GET("/ws/scans/:id", s.handleScanWS)
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": config.Version})
}

type startScanRequest struct {
	Target string `json:"target" binding:"required"`
	Mode   string `json:"mode" binding:"required"`
}

func (s *Server) handleStartScan(c *gin.Context) {
	var req startScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create DB record
	scanRecord := models.Scan{
		TargetName: req.Target,
		Mode:       req.Mode,
		Status:     "pending",
	}
	if err := s.db.Create(&scanRecord).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan record"})
		return
	}

	// Trigger Temporal Workflow
	workflowOptions := client.StartWorkflowOptions{
		ID:        fmt.Sprintf("scan-%d", scanRecord.ID),
		TaskQueue: "reconforge-task-queue",
	}

	input := temporal.ScanInput{
		Target: req.Target,
		Mode:   req.Mode,
	}

	we, err := s.tempClient.ExecuteWorkflow(context.Background(), workflowOptions, temporal.ScanWorkflow, input)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to start temporal workflow")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start workflow"})
		return
	}

	// Update DB with workflow IDs
	scanRecord.WorkflowID = we.GetID()
	scanRecord.RunID = we.GetRunID()
	s.db.Save(&scanRecord)

	s.logger.Info().Str("target", req.Target).Str("mode", req.Mode).Str("workflow_id", we.GetID()).Msg("API: Triggering scan workflow")

	c.JSON(http.StatusAccepted, gin.H{
		"message":     "Scan started",
		"target":      req.Target,
		"scan_id":     scanRecord.ID,
		"workflow_id": we.GetID(),
	})
}

func (s *Server) handleListScans(c *gin.Context) {
	var scans []models.Scan
	if err := s.db.Find(&scans).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch scans"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"scans": scans})
}

// Start runs the HTTP server.
func (s *Server) Start(addr string) error {
	s.logger.Info().Str("addr", addr).Msg("Starting ReconForge API Server")
	return s.router.Run(addr)
}
