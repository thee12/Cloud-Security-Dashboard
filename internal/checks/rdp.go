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
		if isBroadInboundRule(rule, "3389") {
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

func isBroadInboundRule(rule model.NetworkRule, targetPort string) bool {
	inbound := strings.EqualFold(rule.Direction, "Inbound")
	allowed := strings.EqualFold(rule.Access, "Allow")

	matchingProtocol := strings.EqualFold(rule.Protocol, "TCP") ||
		rule.Protocol == "*"

	publicSource := rule.Source == "*" ||
		rule.Source == "0.0.0.0/0" ||
		rule.Source == "::/0"

	matchingPort := rule.DestinationPort == targetPort ||
		rule.DestinationPort == "*"

	return inbound &&
		allowed &&
		matchingProtocol &&
		publicSource &&
		matchingPort
}
