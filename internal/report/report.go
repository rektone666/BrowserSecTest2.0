package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rektone666/browsersec/internal/core"
)

type Paths struct {
	Directory  string
	RawJSON    string
	ReportJSON string
	ReportHTML string
}

func Write(baseDir string, payload core.ScanPayload) (Paths, core.Report, error) {
	rep := core.Evaluate(payload)
	stamp := time.Now().Format("20060102-150405")
	dir := filepath.Join(baseDir, "browsersec-"+stamp)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Paths{}, rep, fmt.Errorf("create report directory: %w", err)
	}
	paths := Paths{
		Directory:  dir,
		RawJSON:    filepath.Join(dir, "raw-scan.json"),
		ReportJSON: filepath.Join(dir, "report.json"),
		ReportHTML: filepath.Join(dir, "report.html"),
	}
	if err := writeJSON(paths.RawJSON, payload); err != nil {
		return paths, rep, err
	}
	if err := writeJSON(paths.ReportJSON, rep); err != nil {
		return paths, rep, err
	}
	if err := writeHTML(paths.ReportHTML, rep); err != nil {
		return paths, rep, err
	}
	return paths, rep, nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

type viewModel struct {
	Report           core.Report
	Groups           []findingGroup
	PassCount        int
	WarnCount        int
	FailCount        int
	InfoCount        int
	UnavailableCount int
}

type findingGroup struct {
	Category string
	Findings []core.Finding
}

func writeHTML(path string, rep core.Report) error {
	groupsByName := map[string][]core.Finding{}
	vm := viewModel{Report: rep}
	for _, item := range rep.Payload.Findings {
		groupsByName[item.Category] = append(groupsByName[item.Category], item)
		switch item.Status {
		case "pass":
			vm.PassCount++
		case "warn":
			vm.WarnCount++
		case "fail":
			vm.FailCount++
		case "info":
			vm.InfoCount++
		case "unavailable":
			vm.UnavailableCount++
		}
	}
	order := []string{"Security controls", "Permissions", "Privacy signals", "Network privacy", "Fingerprinting", "Storage", "Legacy technology", "Capabilities"}
	seen := map[string]bool{}
	for _, name := range order {
		if items := groupsByName[name]; len(items) > 0 {
			vm.Groups = append(vm.Groups, findingGroup{Category: name, Findings: items})
			seen[name] = true
		}
	}
	var rest []string
	for name := range groupsByName {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		vm.Groups = append(vm.Groups, findingGroup{Category: name, Findings: groupsByName[name]})
	}

	funcs := template.FuncMap{
		"lower": strings.ToLower,
		"pretty": func(value any) string {
			if value == nil {
				return ""
			}
			data, _ := json.MarshalIndent(value, "", "  ")
			return string(data)
		},
		"formatTime": func(value time.Time) string { return value.Local().Format("2 Jan 2006, 15:04:05") },
	}
	tpl, err := template.New("report").Funcs(funcs).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("parse report template: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create report.html: %w", err)
	}
	defer file.Close()
	if err := tpl.Execute(file, vm); err != nil {
		return fmt.Errorf("render report.html: %w", err)
	}
	return nil
}

const reportTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BrowserSec Report</title>
<style>
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:#081018;color:#e8eef5;--panel:#111b26;--panel2:#152231;--line:#273748;--muted:#98a8b9;--accent:#62d6b4;--pass:#65d38e;--warn:#f4c96b;--fail:#ff7f88;--info:#79b8ff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#132537 0,#081018 48rem)}main{width:min(1080px,calc(100% - 28px));margin:auto;padding:42px 0 60px}.brand{color:var(--accent);font-weight:800;letter-spacing:.13em;text-transform:uppercase;font-size:.82rem}h1{font-size:clamp(2.2rem,6vw,4.2rem);margin:.3rem 0}.sub{color:var(--muted);max-width:780px;line-height:1.6}.overview{display:grid;grid-template-columns:220px 1fr;gap:18px;margin:26px 0}.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px}.score{display:grid;place-items:center;text-align:center}.score strong{font-size:4rem;line-height:1}.score span{color:var(--muted)}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:18px}.stat{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:12px}.stat strong{font-size:1.35rem;display:block}.stat span{color:var(--muted);font-size:.82rem}.category{margin-top:22px}.finding{margin:10px 0;padding:16px;border:1px solid var(--line);background:var(--panel2);border-radius:12px}.finding-head{display:flex;gap:10px;align-items:center;justify-content:space-between}.finding h3{margin:0;font-size:1rem}.badge{font-size:.72rem;font-weight:800;text-transform:uppercase;padding:5px 9px;border-radius:999px}.pass{background:var(--pass);color:#07150d}.warn{background:var(--warn);color:#1e1602}.fail{background:var(--fail);color:#250307}.info,.unavailable{background:var(--info);color:#061426}.finding p{color:var(--muted);line-height:1.5}.recommendation{border-left:3px solid var(--accent);padding-left:12px;color:#dbe9e5!important}details{margin-top:10px}summary{cursor:pointer;color:#b9c8d7}pre{white-space:pre-wrap;word-break:break-word;background:#071018;border:1px solid var(--line);padding:12px;border-radius:10px;color:#cdd9e5;font-size:.78rem}.category-scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}.category-score{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:14px}.category-score strong{font-size:1.35rem}.category-score span{color:var(--muted);display:block;font-size:.82rem}.notice{border-color:#36506a}.footer{margin-top:26px;color:var(--muted);font-size:.84rem}@media(max-width:700px){.overview{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.finding-head{align-items:flex-start}.card{padding:17px}}
</style></head><body><main>
<div class="brand">BrowserSec Framework v{{.Report.Version}}</div>
<h1>{{.Report.Rating}} · {{.Report.OverallScore}}/100</h1>
<p class="sub">{{.Report.Summary}} This score is a local posture indicator, not a guarantee that the browser or device is secure.</p>
<section class="overview">
<div class="card score"><strong>{{.Report.OverallScore}}</strong><span>browser posture score</span></div>
<div class="card"><h2>Scan summary</h2><p class="sub">Browser: {{.Report.Payload.Meta.BrowserName}}<br>Platform: {{.Report.Payload.Meta.Platform}}<br>Language: {{.Report.Payload.Meta.Language}}<br>Generated: {{formatTime .Report.GeneratedAt}}</p>
<div class="stats"><div class="stat"><strong>{{.PassCount}}</strong><span>Passed</span></div><div class="stat"><strong>{{.WarnCount}}</strong><span>Warnings</span></div><div class="stat"><strong>{{.FailCount}}</strong><span>Failures</span></div><div class="stat"><strong>{{.InfoCount}}</strong><span>Information</span></div><div class="stat"><strong>{{.UnavailableCount}}</strong><span>Unavailable</span></div></div></div>
</section>
<section class="card notice"><h2>What this report means</h2><p class="sub">BrowserSec tests the browser automatically without requesting access to the camera, microphone, location, files, accounts, or passwords. Some exposed capabilities are normal web-platform behavior and are reported as information rather than vulnerabilities.</p></section>
<section class="card"><h2>Category scores</h2><div class="category-scores">{{range .Report.CategoryScores}}<div class="category-score"><strong>{{.Score}}/100</strong><span>{{.Category}}</span><span>{{.Warnings}} warnings · {{.Failures}} failures</span></div>{{end}}</div></section>
{{range .Groups}}<section class="category"><h2>{{.Category}}</h2>{{range .Findings}}<article class="finding"><div class="finding-head"><h3>{{.Name}}</h3><span class="badge {{lower .Status}}">{{.Status}}</span></div><p>{{.Summary}}</p>{{if .Recommendation}}<p class="recommendation"><strong>Suggested action:</strong> {{.Recommendation}}</p>{{end}}{{if .Evidence}}<details><summary>Technical details</summary><pre>{{pretty .Evidence}}</pre></details>{{end}}</article>{{end}}</section>{{end}}
<p class="footer">The complete raw data is stored beside this report in raw-scan.json. All files were generated locally.</p>
</main></body></html>`
