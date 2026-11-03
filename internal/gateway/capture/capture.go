package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// CaptureEngine persists intercepted requests if the captureRequests flag is true
type CaptureEngine struct {
	Enabled   bool
	OutputDir string
}

func NewCaptureEngine(enabled bool, outputDir string) *CaptureEngine {
	return &CaptureEngine{
		Enabled:   enabled,
		OutputDir: outputDir,
	}
}

func (c *CaptureEngine) Record(ctx *model.AuthenticationContext) error {
	if !c.Enabled {
		return nil
	}

	if err := os.MkdirAll(c.OutputDir, 0755); err != nil {
		return err
	}

	filename := filepath.Join(c.OutputDir, fmt.Sprintf("req_%s_%s.json", time.Now().Format("20060102150405"), ctx.RequestID))
	
	// Create safe snapshot
	snapshot := map[string]interface{}{
		"request_id":       ctx.RequestID,
		"original_ip":      ctx.OriginalClientIP,
		"raw_xml":          string(ctx.RawXML),
		"relay_state":      ctx.RelayState,
		"received_at":      ctx.ReceivedAt,
		"binding":          ctx.RequestBinding,
		"validation_state": ctx.ValidationResult,
		"pipeline_metrics": ctx.Metrics,
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
