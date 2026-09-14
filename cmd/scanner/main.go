package main

import (
	"encoding/json"
	"fmt"
	"os"

	"cloud-security-dashboard/internal/checks"
	"cloud-security-dashboard/internal/model"
)

func main() {
	data, err := os.ReadFile("fixtures/resources.json")
	if err != nil {
		fmt.Printf("Could not read fixture file: %v\n", err)
		os.Exit(1)
	}

	var resources []model.Resource

	err = json.Unmarshal(data, &resources)
	if err != nil {
		fmt.Printf("Could not parse fixture file: %v\n", err)
		os.Exit(1)
	}

	var results []model.CheckResult

	for _, resource := range resources {
		if resource.Type == "network_security_group" {
			result := checks.CheckBroadRDPIngress(resource)
			results = append(results, result)
		}
	}

	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Could not create results: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
