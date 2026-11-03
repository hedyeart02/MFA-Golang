package capture

import (
	"testing"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

func TestITAIntegrationHarness(t *testing.T) {
	// Simulated context that the pipeline WOULD return
	ctx := &model.AuthenticationContext{
		RequestID: "ITA-MOCK-123",
		RawXML:    []byte("<samlp:AuthnRequest/>"),
	}

	engine := NewCaptureEngine(true, "../../../testdata/ita")
	
	err := engine.Record(ctx)
	if err != nil {
		t.Fatalf("Failed to capture ITA harness output: %v", err)
	}
}
