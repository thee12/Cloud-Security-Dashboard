package checks

import "cloud-security-dashboard/internal/model"

const BroadSSHCheckID = "AZURE-NSG-002"

func CheckBroadSSHIngress(resource model.Resource) model.CheckResult {
	if resource.Rules == nil {
		return model.CheckResult{
			CheckID:    BroadSSHCheckID,
			ResourceID: resource.ID,
			Status:     "UNKNOWN",
			Severity:   "HIGH",
			Message:    "Network security rules were unavailable, so SSH exposure could not be evaluated.",
			Evidence: map[string]any{
				"reason": "missing rule data",
			},
		}
	}

	result := model.CheckResult{
		CheckID:    BroadSSHCheckID,
		ResourceID: resource.ID,
		Status:     "PASS",
		Severity:   "HIGH",
		Message:    "No internet-wide inbound SSH rule was detected.",
	}

	for _, rule := range resource.Rules {
		if isBroadInboundRule(rule, "22") {
			result.Status = "FAIL"
			result.Message = "SSH is allowed from the public internet."
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
