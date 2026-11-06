//go:build windows

package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/sys/windows/svc"
)

func TestIsWindowsService_InteractiveRunner(t *testing.T) {
	// Under standard go test execution, process is running interactively
	if isWindowsService() {
		t.Fatalf("expected isWindowsService() to return false in interactive test runner")
	}
}

func TestWindowsServiceHandler_Lifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	zapLogger, _ := zap.NewDevelopment()
	appLog := logger.New(zapLogger)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:            "127.0.0.1",
			Port:            0,
			ShutdownTimeout: 5 * time.Second,
		},
	}

	engine := gin.New()
	srv := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: engine,
	}

	service := &samlguardService{
		srv:       srv,
		cfg:       cfg,
		appLogger: appLog,
	}

	reqChan := make(chan svc.ChangeRequest, 5)
	statusChan := make(chan svc.Status, 10)

	execDone := make(chan struct{})
	var sec bool
	var ec uint32

	go func() {
		sec, ec = service.Execute([]string{"SAMLGuard"}, reqChan, statusChan)
		close(execDone)
	}()

	// 1. Verify StartPending reported
	select {
	case st := <-statusChan:
		if st.State != svc.StartPending {
			t.Fatalf("expected StartPending, got %v", st.State)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for StartPending status")
	}

	// 2. Verify Running reported with AcceptStop | AcceptShutdown
	select {
	case st := <-statusChan:
		if st.State != svc.Running {
			t.Fatalf("expected Running, got %v", st.State)
		}
		expectedAccepts := svc.AcceptStop | svc.AcceptShutdown
		if st.Accepts != expectedAccepts {
			t.Fatalf("expected accepts %v, got %v", expectedAccepts, st.Accepts)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Running status")
	}

	// 3. Test svc.Interrogate
	reqChan <- svc.ChangeRequest{
		Cmd:           svc.Interrogate,
		CurrentStatus: svc.Status{State: svc.Running},
	}
	select {
	case st := <-statusChan:
		if st.State != svc.Running {
			t.Fatalf("expected Running in interrogate response, got %v", st.State)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Interrogate response")
	}

	// 4. Test svc.Stop
	reqChan <- svc.ChangeRequest{
		Cmd: svc.Stop,
	}

	// Verify StopPending reported
	select {
	case st := <-statusChan:
		if st.State != svc.StopPending {
			t.Fatalf("expected StopPending, got %v", st.State)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for StopPending status")
	}

	// Verify Stopped reported
	select {
	case st := <-statusChan:
		if st.State != svc.Stopped {
			t.Fatalf("expected Stopped, got %v", st.State)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Stopped status")
	}

	// Verify Execute returned (false, 0)
	select {
	case <-execDone:
		if sec != false || ec != 0 {
			t.Fatalf("expected (false, 0), got (%v, %d)", sec, ec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Execute to return")
	}
}

func TestWindowsServiceHandler_ShutdownCommand(t *testing.T) {
	gin.SetMode(gin.TestMode)
	zapLogger, _ := zap.NewDevelopment()
	appLog := logger.New(zapLogger)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:            "127.0.0.1",
			Port:            0,
			ShutdownTimeout: 5 * time.Second,
		},
	}

	srv := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: gin.New(),
	}

	service := &samlguardService{
		srv:       srv,
		cfg:       cfg,
		appLogger: appLog,
	}

	reqChan := make(chan svc.ChangeRequest, 5)
	statusChan := make(chan svc.Status, 10)

	execDone := make(chan struct{})

	go func() {
		_, _ = service.Execute([]string{"SAMLGuard"}, reqChan, statusChan)
		close(execDone)
	}()

	// Drain StartPending & Running
	select {
	case <-statusChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for StartPending")
	}

	select {
	case <-statusChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Running")
	}

	// Test svc.Shutdown
	reqChan <- svc.ChangeRequest{Cmd: svc.Shutdown}

	// Verify StopPending
	select {
	case stStopPending := <-statusChan:
		if stStopPending.State != svc.StopPending {
			t.Fatalf("expected StopPending, got %v", stStopPending.State)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for StopPending")
	}

	// Verify Stopped
	select {
	case stStopped := <-statusChan:
		if stStopped.State != svc.Stopped {
			t.Fatalf("expected Stopped, got %v", stStopped.State)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Stopped")
	}

	select {
	case <-execDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Execute to return")
	}
}

