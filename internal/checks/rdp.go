package checks

import (
	"strings"

	"cloud-security-dashboard/internal/model"
)

const BroadRDPCheckID = "AZURE-NSG-001"

func CheckBroadRDPIngress(resource model.Resource) model.CheckResult {
	if resource.Rules == nil {
		return model.CheckResult{
			CheckID:    BroadRDPCheckID,
			ResourceID: resource.ID,
			Status:     "UNKNOWN",
			Severity:   "HIGH",
			Message:    "Network security rules were unavailable, so RDP exposure could not be evaluated.",
			Evidence: map[string]any{
				"reason": "missing rule data",
			},
		}
	}
	result := model.CheckResult{
		CheckID:    BroadRDPCheckID,
		ResourceID: resource.ID,
		Status:     "PASS",
		Severity:   "HIGH",
		Message:    "No internet-wide inbound RDP rule was detected.",
	}

	for _, rule := range resource.Rules {
		if isBroadRDPRule(rule) {
			result.Status = "FAIL"
			result.Message = "RDP is allowed from the public internet."
			result.Evidence = map[string]any{
				"ruleName":        rule.Name,
				"source":          rule.Source,
				"destinationPort": rule.DestinationPort,
				"priority":        rule.Priority,
			}

			return result
		}
	}

	return result
}

func isBroadRDPRule(rule model.NetworkRule) bool {
	inbound := strings.EqualFold(rule.Direction, "Inbound")
	allowed := strings.EqualFold(rule.Access, "Allow")

	tcp := strings.EqualFold(rule.Protocol, "TCP") ||
		rule.Protocol == "*"

	publicSource := rule.Source == "*" ||
		rule.Source == "0.0.0.0/0" ||
		rule.Source == "::/0"

	rdpPort := rule.DestinationPort == "3389" ||
		rule.DestinationPort == "*"

	return inbound && allowed && tcp && publicSource && rdpPort
}
