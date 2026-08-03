package core

import "time"

const Version = "0.1.0"

type Finding struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Category       string         `json:"category"`
	Status         string         `json:"status"`
	Severity       string         `json:"severity"`
	Summary        string         `json:"summary"`
	Evidence       map[string]any `json:"evidence,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
}

type ScanMeta struct {
	Version      string `json:"version"`
	StartedAt    string `json:"startedAt"`
	CompletedAt  string `json:"completedAt"`
	Origin       string `json:"origin"`
	UserAgent    string `json:"userAgent"`
	BrowserName  string `json:"browserName,omitempty"`
	Platform     string `json:"platform,omitempty"`
	Language     string `json:"language,omitempty"`
	ScanDuration int64  `json:"scanDurationMs,omitempty"`
}

type ScanPayload struct {
	Meta         ScanMeta       `json:"meta"`
	Findings     []Finding      `json:"findings"`
	Observations map[string]any `json:"observations,omitempty"`
}

type CategoryScore struct {
	Category string `json:"category"`
	Score    int    `json:"score"`
	Warnings int    `json:"warnings"`
	Failures int    `json:"failures"`
}

type Report struct {
	GeneratedAt    time.Time       `json:"generatedAt"`
	Version        string          `json:"version"`
	OverallScore   int             `json:"overallScore"`
	Rating         string          `json:"rating"`
	Summary        string          `json:"summary"`
	CategoryScores []CategoryScore `json:"categoryScores"`
	Payload        ScanPayload     `json:"payload"`
}

func Evaluate(payload ScanPayload) Report {
	weights := map[string]int{"high": 15, "medium": 8, "low": 3, "none": 0}
	statusFactor := map[string]float64{"fail": 1, "warn": 0.65, "pass": 0, "info": 0, "unavailable": 0}

	totalPenalty := 0.0
	type catState struct {
		penalty float64
		count   int
		warn    int
		fail    int
	}
	cats := map[string]*catState{}

	for _, finding := range payload.Findings {
		weight := weights[finding.Severity]
		factor := statusFactor[finding.Status]
		penalty := float64(weight) * factor
		totalPenalty += penalty

		state := cats[finding.Category]
		if state == nil {
			state = &catState{}
			cats[finding.Category] = state
		}
		state.penalty += penalty
		state.count++
		if finding.Status == "warn" {
			state.warn++
		}
		if finding.Status == "fail" {
			state.fail++
		}
	}

	score := 100 - int(totalPenalty+0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	rating := "Strong"
	summary := "No major browser-security or privacy exposure was detected by the automatic checks."
	switch {
	case score < 40:
		rating = "Weak"
		summary = "Several important browser-security or privacy findings need attention."
	case score < 65:
		rating = "Needs attention"
		summary = "The browser exposes multiple security or privacy weaknesses worth reviewing."
	case score < 85:
		rating = "Good"
		summary = "The browser has a generally good posture, with some privacy or hardening improvements available."
	}

	categoryOrder := []string{"Security controls", "Permissions", "Privacy signals", "Network privacy", "Fingerprinting", "Storage", "Legacy technology", "Capabilities"}
	categoryScores := make([]CategoryScore, 0, len(cats))
	seen := map[string]bool{}
	appendCategory := func(name string, state *catState) {
		categoryScore := 100 - int(state.penalty+0.5)
		if categoryScore < 0 {
			categoryScore = 0
		}
		categoryScores = append(categoryScores, CategoryScore{Category: name, Score: categoryScore, Warnings: state.warn, Failures: state.fail})
		seen[name] = true
	}
	for _, name := range categoryOrder {
		if state := cats[name]; state != nil {
			appendCategory(name, state)
		}
	}
	for name, state := range cats {
		if !seen[name] {
			appendCategory(name, state)
		}
	}

	return Report{
		GeneratedAt:    time.Now(),
		Version:        Version,
		OverallScore:   score,
		Rating:         rating,
		Summary:        summary,
		CategoryScores: categoryScores,
		Payload:        payload,
	}
}
