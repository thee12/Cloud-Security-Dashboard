package checks

import (
	"testing"

	"cloud-security-dashboard/internal/model"
)

func TestCheckBroadSSHIngress(t *testing.T) {
	tests := []struct {
		name       string
		rule       model.NetworkRule
		wantStatus string
	}{
		{
			name: "public SSH should fail",
			rule: model.NetworkRule{
				Name:            "AllowPublicSSH",
				Direction:       "Inbound",
				Access:          "Allow",
				Protocol:        "TCP",
				Source:          "0.0.0.0/0",
				DestinationPort: "22",
				Priority:        100,
			},
			wantStatus: "FAIL",
		},
		{
			name: "private SSH should pass",
			rule: model.NetworkRule{
				Name:            "AllowPrivateSSH",
				Direction:       "Inbound",
				Access:          "Allow",
				Protocol:        "TCP",
				Source:          "10.0.0.0/24",
				DestinationPort: "22",
				Priority:        100,
			},
			wantStatus: "PASS",
		},
		{
			name: "public RDP should pass the SSH check",
			rule: model.NetworkRule{
				Name:            "AllowPublicRDP",
				Direction:       "Inbound",
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

			result := CheckBroadSSHIngress(resource)

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

func TestCheckBroadSSHIngressReturnsUnknownWhenRulesAreMissing(t *testing.T) {
	resource := model.Resource{
		ID:       "missing-rules-resource",
		Name:     "unknown-nsg",
		Provider: "azure",
		Type:     "network_security_group",
		Rules:    nil,
	}

	result := CheckBroadSSHIngress(resource)

	if result.Status != "UNKNOWN" {
		t.Errorf(
			"expected status UNKNOWN, received %s",
			result.Status,
		)
	}
}
