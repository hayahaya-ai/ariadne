package remediate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/hayahaya-ai/ariadne/internal/scan"
)

func RenderFromFile(w io.Writer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var report scan.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return err
	}
	if len(report.Remediations) == 0 {
		fmt.Fprintln(w, "No remediation snippets are available in this report.")
		return nil
	}
	fmt.Fprintln(w, "# Ariadne Remediation Guidance")
	fmt.Fprintln(w)
	for _, remediation := range report.Remediations {
		fmt.Fprintf(w, "## %s\n\n", remediation.Title)
		fmt.Fprintf(w, "- Applies to: %s\n", remediation.AppliesTo)
		fmt.Fprintf(w, "- Behavioral impact: %s\n\n", remediation.BehavioralImpact)
		if remediation.Snippet != "" {
			fmt.Fprintf(w, "```text\n%s\n```\n\n", remediation.Snippet)
		}
		for _, step := range remediation.ManualSteps {
			fmt.Fprintf(w, "- %s\n", step)
		}
		fmt.Fprintln(w)
	}
	return nil
}
