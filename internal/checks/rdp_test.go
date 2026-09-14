package checks

import (
	"testing"

	"cloud-security-dashboard/internal/model"
)

func TestCheckBroadRDPIngress(t *testing.T) {
	tests := []struct {
		name       string
		rule       model.NetworkRule
		wantStatus string
	}{
		{
			name: "public RDP should fail",
			rule: model.NetworkRule{
				Name:            "AllowPublicRDP",
				Direction:       "Inbound",
				Access:          "Allow",
				Protocol:        "TCP",
				Source:          "0.0.0.0/0",
				DestinationPort: "3389",
				Priority:        100,
			},
			wantStatus: "FAIL",
		},
		{
			name: "private RDP should pass",
			rule: model.NetworkRule{
				Name:            "AllowPrivateRDP",
				Direction:       "Inbound",
				Access:          "Allow",
				Protocol:        "TCP",
				Source:          "10.0.0.0/24",
				DestinationPort: "3389",
				Priority:        100,
			},
			wantStatus: "PASS",
		},
		{
			name: "public HTTPS should pass",
			rule: model.NetworkRule{
				Name:            "AllowHTTPS",
				Direction:       "Inbound",
				Access:          "Allow",
				Protocol:        "TCP",
				Source:          "0.0.0.0/0",
				DestinationPort: "443",
				Priority:        100,
			},
			wantStatus: "PASS",
		},
		{
			name: "outbound RDP should pass",
			rule: model.NetworkRule{
				Name:            "AllowOutboundRDP",
				Direction:       "Outbound",
				Access:          "Allow",
				Protocol:        "TCP",
				Source:          "0.0.0.0/0",
				DestinationPort: "3389",
				Priority:        100,
			},
			wantStatus: "PASS",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := model.Resource{
				ID:       "test-resource",
				Name:     "test-nsg",
				Provider: "azure",
				Type:     "network_security_group",
				Rules:    []model.NetworkRule{test.rule},
			}

			result := CheckBroadRDPIngress(resource)

			if result.Status != test.wantStatus {
				t.Errorf(
					"expected status %s, received %s",
					test.wantStatus,
					result.Status,
				)
			}
		})
	}
}

func TestCheckBroadRDPIngressReturnsUnknownWhenRulesAreMissing(t *testing.T) {
	resource := model.Resource{
		ID:       "missing-rules-resource",
		Name:     "unknown-nsg",
		Provider: "azure",
		Type:     "network_security_group",
		Rules:    nil,
	}

	result := CheckBroadRDPIngress(resource)

	if result.Status != "UNKNOWN" {
		t.Errorf(
			"expected status UNKNOWN, received %s",
			result.Status,
		)
	}
}
