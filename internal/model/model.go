package model

type NetworkRule struct {
	Name            string `json:"name"`
	Direction       string `json:"direction"`
	Access          string `json:"access"`
	Protocol        string `json:"protocol"`
	Source          string `json:"source"`
	DestinationPort string `json:"destinationPort"`
	Priority        int    `json:"priority"`
}

type Resource struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Provider string        `json:"provider"`
	Type     string        `json:"type"`
	Rules    []NetworkRule `json:"rules"`
}

type CheckResult struct {
	CheckID    string         `json:"checkId"`
	ResourceID string         `json:"resourceId"`
	Status     string         `json:"status"`
	Severity   string         `json:"severity"`
	Message    string         `json:"message"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}
