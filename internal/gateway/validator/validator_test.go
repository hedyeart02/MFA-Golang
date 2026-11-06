package validator

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

func TestSignatureValidator_FailClosed(t *testing.T) {
	v := &DefaultSignatureValidator{}
	ctx := &model.AuthenticationContext{
		RequestID: "req-1",
		Issuer:    "https://sp.example.com",
	}

	err := v.ValidateSignature(ctx)
	if err == nil {
		t.Fatal("expected fail-closed error from signature validator, got nil")
	}
	if ctx.SecurityFlags.IsSigned {
		t.Error("expected IsSigned to remain false")
	}
}

func TestReplayValidator_DetectionAndConcurrency(t *testing.T) {
	v := NewDefaultReplayValidator(1 * time.Minute)

	ctx1 := &model.AuthenticationContext{RequestIDFromSP: "unique-req-1"}

	// First attempt should succeed
	if err := v.ValidateReplay(ctx1); err != nil {
		t.Fatalf("first validation failed: %v", err)
	}

	// Immediate replay attempt with the same ID must be rejected
	if err := v.ValidateReplay(ctx1); err == nil {
		t.Fatal("expected replay attack error, got nil")
	}

	// Concurrency test: ensure no data races across goroutines
	var wg sync.WaitGroup
	workers := 50
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			reqID := fmt.Sprintf("concurrent-req-%d", id)
			ctx := &model.AuthenticationContext{RequestIDFromSP: reqID}
			_ = v.ValidateReplay(ctx)
		}(i)
	}
	wg.Wait()
}

func TestSyntaxValidator(t *testing.T) {
	v := &DefaultSyntaxValidator{MaxXMLSize: 100}

	// Valid XML
	ctxValid := &model.AuthenticationContext{
		RawXML: []byte("<valid>test</valid>"),
	}
	if err := v.ValidateSyntax(ctxValid); err != nil {
		t.Fatalf("unexpected syntax error: %v", err)
	}

	// Empty XML
	ctxEmpty := &model.AuthenticationContext{RawXML: []byte{}}
	if err := v.ValidateSyntax(ctxEmpty); err == nil {
		t.Fatal("expected error for empty raw XML, got nil")
	}

	// Oversized XML
	ctxOversized := &model.AuthenticationContext{
		RawXML: []byte("<root>" + string(make([]byte, 200)) + "</root>"),
	}
	if err := v.ValidateSyntax(ctxOversized); err == nil {
		t.Fatal("expected error for oversized raw XML, got nil")
	}

	// Invalid UTF-8
	ctxInvalidUTF8 := &model.AuthenticationContext{
		RawXML: []byte{0xff, 0xfe, 0xfd},
	}
	if err := v.ValidateSyntax(ctxInvalidUTF8); err == nil {
		t.Fatal("expected error for invalid UTF-8 in raw XML, got nil")
	}
}

func TestSchemaValidator(t *testing.T) {
	v := &DefaultSchemaValidator{}

	// Valid issuer
	ctxValid := &model.AuthenticationContext{Issuer: "https://idp.example.com"}
	if err := v.ValidateSchema(ctxValid); err != nil {
		t.Fatalf("unexpected schema error: %v", err)
	}

	// Missing issuer
	ctxMissing := &model.AuthenticationContext{Issuer: ""}
	if err := v.ValidateSchema(ctxMissing); err == nil {
		t.Fatal("expected error for missing issuer, got nil")
	}
}

func TestClockValidator(t *testing.T) {
	v := &DefaultClockValidator{AllowedSkew: 2 * time.Minute}

	// Recent issue instant
	ctxRecent := &model.AuthenticationContext{
		IssueInstant: time.Now().Add(-30 * time.Second),
	}
	if err := v.ValidateClockSkew(ctxRecent); err != nil {
		t.Fatalf("unexpected clock skew error: %v", err)
	}

	// Stale issue instant beyond allowed skew
	ctxStale := &model.AuthenticationContext{
		IssueInstant: time.Now().Add(-10 * time.Minute),
	}
	if err := v.ValidateClockSkew(ctxStale); err == nil {
		t.Fatal("expected clock skew error for stale instant, got nil")
	}
}

func TestPolicyValidator(t *testing.T) {
	v := &DefaultPolicyValidator{
		ExpectedDestination: "https://samlguard.example/saml/sso",
	}

	// Matching destination
	ctxMatch := &model.AuthenticationContext{
		Destination: "https://samlguard.example/saml/sso",
	}
	if err := v.ValidatePolicy(ctxMatch); err != nil {
		t.Fatalf("unexpected policy error: %v", err)
	}

	// Mismatched destination
	ctxMismatch := &model.AuthenticationContext{
		Destination: "https://other.example/saml/sso",
	}
	if err := v.ValidatePolicy(ctxMismatch); err == nil {
		t.Fatal("expected destination mismatch error, got nil")
	}
}

