package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"cloud-security-dashboard/internal/checks"
	"cloud-security-dashboard/internal/model"
	"cloud-security-dashboard/internal/store"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data, err := os.ReadFile("fixtures/resources.json")
	if err != nil {
		fmt.Printf("Could not read fixture file: %v\n", err)
		os.Exit(1)
	}

	var resources []model.Resource

	if err := json.Unmarshal(data, &resources); err != nil {
		fmt.Printf("Could not parse fixture file: %v\n", err)
		os.Exit(1)
	}

	var results []model.CheckResult

	for _, resource := range resources {
		if resource.Type == "network_security_group" {
			rdpResult := checks.CheckBroadRDPIngress(resource)
			sshResult := checks.CheckBroadSSHIngress(resource)

			results = append(results, rdpResult, sshResult)
		}
	}

	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Could not create results: %v\n", err)
		os.Exit(1)
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fmt.Println("DATABASE_URL is not configured")
		os.Exit(1)
	}

	pool, err := store.Open(ctx, databaseURL)
	if err != nil {
		fmt.Printf("Could not open database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	scanID, err := store.CreateScan(ctx, pool, "fixture")
	if err != nil {
		fmt.Printf("Could not create scan: %v\n", err)
		os.Exit(1)
	}

	if err := store.CompleteScan(ctx, pool, scanID); err != nil {
		fmt.Printf("Could not complete scan: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
	fmt.Printf("\nSaved scan %d to PostgreSQL.\n", scanID)
}
