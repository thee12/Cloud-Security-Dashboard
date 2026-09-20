package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"cloud-security-dashboard/internal/checks"
	"cloud-security-dashboard/internal/model"
	"cloud-security-dashboard/internal/store"
)

func main() {
	inputPath := flag.String(
		"input",
		"fixtures/resources.json",
		"path to the resource fixture file",
	)

	source := flag.String(
		"source",
		"fixture",
		"label describing the scan source",
	)

	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Printf("Could not read input file %s: %v\n", *inputPath, err)
		os.Exit(1)
	}

	var resources []model.Resource

	if err := json.Unmarshal(data, &resources); err != nil {
		fmt.Printf("Could not parse input file %s: %v\n", *inputPath, err)
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

	scanID, err := store.SaveScan(
		ctx,
		pool,
		*source,
		resources,
		results,
	)
	if err != nil {
		fmt.Printf("Could not save scan: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
	fmt.Printf("\nSaved scan %d to PostgreSQL.\n", scanID)
}
