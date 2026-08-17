package main

import (
	"fmt"
	"os"
	"path/filepath"

	"scanvault/internal/batch"
	"scanvault/internal/model"
	"scanvault/internal/report"
	"scanvault/internal/service"
	"scanvault/internal/store"
)

func main() {
	path := filepath.Join(os.TempDir(), "scanvault-smoke.db")
	_ = os.Remove(path)
	database, err := store.Open(path)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer database.Close()
	application := service.New(database, "smoke", "2026-01-01T00:00:00Z")
	device, err := application.RegisterDevice("SMOKE-001", "Smoke Scanner", "public-smoke-key", "lab", "operator", "operator")
	if err != nil {
		fmt.Println("register:", err)
		return
	}
	envelope, request, err := application.RotateSecret(device.ID, "smoke-secret-123", "operator", "initial setup")
	if err != nil {
		fmt.Println("rotate:", err)
		return
	}
	if _, err := application.ApproveRotation(request.ID, "reviewer", "approved for smoke"); err != nil {
		fmt.Println("approve:", err)
		return
	}
	if _, err := application.MarkApplied(request.ID, "operator"); err != nil {
		fmt.Println("apply:", err)
		return
	}
	recovered, err := application.RecoverSecret(device.ID, "private-smoke-key", envelope.ID)
	if err != nil {
		fmt.Println("recover:", err)
		return
	}
	_ = recovered
	entries, err := application.Audit.List()
	if err != nil {
		fmt.Println("audit:", err)
		return
	}
	builder := report.NewBuilder("scanvault smoke")
	text, err := report.RenderCSV(builder.Rows(entries))
	if err != nil {
		fmt.Println("report:", err)
		return
	}
	fmt.Printf("device=%s envelope=%s audit=%d\n%s", device.ID, envelope.ID, len(entries), text)
	_ = batch.CountAccepted
	_ = model.NormalizeSerial
}
