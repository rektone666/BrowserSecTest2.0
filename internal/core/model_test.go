package core

import "testing"

func TestEvaluateNoPenalty(t *testing.T) {
	payload := ScanPayload{Findings: []Finding{{ID: "a", Category: "Security controls", Status: "pass", Severity: "none"}}}
	report := Evaluate(payload)
	if report.OverallScore != 100 {
		t.Fatalf("expected 100, got %d", report.OverallScore)
	}
	if report.Rating != "Strong" {
		t.Fatalf("expected Strong, got %q", report.Rating)
	}
}

func TestEvaluateWeightedPenalty(t *testing.T) {
	payload := ScanPayload{Findings: []Finding{
		{ID: "high", Category: "Security controls", Status: "fail", Severity: "high"},
		{ID: "medium", Category: "Network privacy", Status: "warn", Severity: "medium"},
	}}
	report := Evaluate(payload)
	// high failure = 15, medium warning = 8 * 0.65 = 5.2, rounded total score = 80.
	if report.OverallScore != 80 {
		t.Fatalf("expected 80, got %d", report.OverallScore)
	}
	if len(report.CategoryScores) != 2 {
		t.Fatalf("expected 2 category scores, got %d", len(report.CategoryScores))
	}
}
