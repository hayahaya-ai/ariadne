package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

type ProofPatchExportResult struct {
	Directory       string
	ManifestPath    string
	ReadmePath      string
	Files           []string
	FileDetails     []ProofPatchExportFileResult
	PatchCount      int
	ClosureControls []string
	ClosureFiles    []string
	ClosureRule     string
}

type ProofPatchExportFileResult struct {
	Path                 string
	GeneratedPath        string
	Surface              string
	SuggestedDestination string
	DestinationPath      string
	ApplyCommand         string
	Format               string
	Controls             []string
	PatchCount           int
}

type proofPatchExportManifest struct {
	SchemaVersion   string                         `json:"schema_version"`
	GeneratedAt     time.Time                      `json:"generated_at"`
	RunID           string                         `json:"run_id"`
	TargetPath      string                         `json:"target_path"`
	Mode            string                         `json:"mode"`
	Agent           string                         `json:"agent"`
	StatusFilter    string                         `json:"status_filter"`
	CaseFilter      string                         `json:"case_filter"`
	PatchCount      int                            `json:"patch_count"`
	ClosureControls []string                       `json:"closure_controls"`
	ClosureFiles    []string                       `json:"closure_files"`
	ClosureRule     string                         `json:"closure_rule"`
	Files           []proofPatchExportManifestFile `json:"files"`
	RerunCommands   []string                       `json:"rerun_commands"`
	CompareCommands []string                       `json:"compare_commands"`
	Workflow        []model.ProofWorkflowStep      `json:"workflow"`
	Limitations     []string                       `json:"limitations"`
}

type proofPatchExportManifestFile struct {
	Path                 string   `json:"path"`
	Surface              string   `json:"surface"`
	SuggestedDestination string   `json:"suggested_destination"`
	DestinationPath      string   `json:"destination_path,omitempty"`
	ApplyCommand         string   `json:"apply_command,omitempty"`
	Format               string   `json:"format"`
	Controls             []string `json:"controls"`
	PatchCount           int      `json:"patch_count"`
	Summaries            []string `json:"summaries"`
	Limitations          []string `json:"limitations"`
}

type proofPatchSurfaceExport struct {
	Surface     string
	Format      string
	Patches     []model.ControlProofPatch
	Fields      map[string]string
	Controls    []string
	Summaries   []string
	Limitations []string
}

func ExportProofPatchFiles(dir string, plan model.ProofPlanReport) (ProofPatchExportResult, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ProofPatchExportResult{}, fmt.Errorf("proof patch export directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ProofPatchExportResult{}, err
	}
	groups := proofPatchSurfaceExports(plan.ProofPatches)
	closureControls := proofPatchControls(plan.ProofPatches)
	closureFiles := proofPatchExportClosureFiles(groups)
	closureRule := proofPatchExportClosureRule()
	result := ProofPatchExportResult{
		Directory:       dir,
		PatchCount:      len(plan.ProofPatches),
		ClosureControls: append([]string{}, closureControls...),
		ClosureFiles:    append([]string{}, closureFiles...),
		ClosureRule:     closureRule,
	}
	manifest := proofPatchExportManifest{
		SchemaVersion:   model.SchemaVersion,
		GeneratedAt:     plan.GeneratedAt,
		RunID:           plan.RunID,
		TargetPath:      plan.TargetPath,
		Mode:            plan.Mode,
		Agent:           plan.Agent,
		StatusFilter:    plan.StatusFilter,
		CaseFilter:      plan.CaseFilter,
		PatchCount:      len(plan.ProofPatches),
		ClosureControls: closureControls,
		ClosureFiles:    closureFiles,
		ClosureRule:     closureRule,
		Files:           []proofPatchExportManifestFile{},
		RerunCommands:   append([]string{}, plan.RerunCommands...),
		CompareCommands: append([]string{}, plan.CompareCommands...),
		Workflow:        append([]model.ProofWorkflowStep{}, plan.Workflow...),
		Limitations: uniqueSortedStrings(append([]string{
			"Exported proof files are suggested evidence artifacts only; review them before copying into a repo or endpoint configuration.",
			"Exporting proof files does not prove that the named control is live or enforced.",
		}, plan.Limitations...)),
	}
	for _, group := range groups {
		relPath := proofPatchExportSurfaceRelPath(group.Surface)
		absPath := filepath.Join(dir, relPath)
		if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
			return ProofPatchExportResult{}, err
		}
		if err := os.WriteFile(absPath, []byte(proofPatchSurfaceExportContent(group)), 0o644); err != nil {
			return ProofPatchExportResult{}, err
		}
		result.Files = append(result.Files, absPath)
		destinationPath := proofPatchSuggestedDestinationPath(plan.TargetPath, group.Surface)
		applyCommand := proofPatchApplyCommand(dir, relPath, destinationPath)
		result.FileDetails = append(result.FileDetails, ProofPatchExportFileResult{
			Path:                 relPath,
			GeneratedPath:        absPath,
			Surface:              group.Surface,
			SuggestedDestination: group.Surface,
			DestinationPath:      destinationPath,
			ApplyCommand:         applyCommand,
			Format:               group.Format,
			Controls:             append([]string{}, group.Controls...),
			PatchCount:           len(group.Patches),
		})
		manifest.Files = append(manifest.Files, proofPatchExportManifestFile{
			Path:                 relPath,
			Surface:              group.Surface,
			SuggestedDestination: group.Surface,
			DestinationPath:      destinationPath,
			ApplyCommand:         applyCommand,
			Format:               group.Format,
			Controls:             group.Controls,
			PatchCount:           len(group.Patches),
			Summaries:            group.Summaries,
			Limitations:          group.Limitations,
		})
	}
	readmePath := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readmePath, []byte(proofPatchExportReadme(plan, manifest)), 0o644); err != nil {
		return ProofPatchExportResult{}, err
	}
	result.ReadmePath = readmePath
	manifestPath := filepath.Join(dir, "manifest.json")
	blob, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ProofPatchExportResult{}, err
	}
	blob = append(blob, '\n')
	if err := os.WriteFile(manifestPath, blob, 0o644); err != nil {
		return ProofPatchExportResult{}, err
	}
	result.ManifestPath = manifestPath
	return result, nil
}

func proofPatchExportClosureRule() string {
	return "Rerun must show every bundle control is no longer a missing hard barrier for this case."
}

func proofPatchExportClosureFiles(groups []proofPatchSurfaceExport) []string {
	var out []string
	for _, group := range groups {
		out = append(out, proofPatchExportSurfaceRelPath(group.Surface))
	}
	return uniqueStrings(out)
}

func proofPatchSurfaceExports(patches []model.ControlProofPatch) []proofPatchSurfaceExport {
	bySurface := map[string]*proofPatchSurfaceExport{}
	for _, patch := range patches {
		surface := strings.TrimSpace(patch.Surface)
		if surface == "" {
			surface = "supported-control-evidence.txt"
		}
		group := bySurface[surface]
		if group == nil {
			group = &proofPatchSurfaceExport{
				Surface: surface,
				Format:  firstNonEmpty(patch.Format, controlProofPatchFormat(surface)),
				Fields:  map[string]string{},
			}
			bySurface[surface] = group
		}
		group.Patches = append(group.Patches, patch)
		if patch.Control != "" {
			group.Controls = append(group.Controls, patch.Control)
		}
		if patch.Summary != "" {
			group.Summaries = append(group.Summaries, patch.Summary)
		}
		group.Limitations = append(group.Limitations, patch.Limitations...)
		for _, field := range patch.Fields {
			if field.Name == "" {
				continue
			}
			if _, exists := group.Fields[field.Name]; !exists {
				group.Fields[field.Name] = normalizeJSONLiteral(field.ValueJSON)
			}
		}
	}
	var out []proofPatchSurfaceExport
	for _, group := range bySurface {
		group.Controls = uniqueSortedStrings(group.Controls)
		group.Summaries = uniqueSortedStrings(group.Summaries)
		group.Limitations = uniqueSortedStrings(group.Limitations)
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Surface < out[j].Surface
	})
	if out == nil {
		return []proofPatchSurfaceExport{}
	}
	return out
}

func proofPatchSurfaceExportContent(group proofPatchSurfaceExport) string {
	switch group.Format {
	case "toml_snippet":
		return proofPatchSurfaceExportTOML(group)
	case "markdown_list":
		return proofPatchSurfaceExportMarkdown(group)
	default:
		return proofPatchSurfaceExportJSON(group)
	}
}

func proofPatchSurfaceExportJSON(group proofPatchSurfaceExport) string {
	names := sortedMapKeys(group.Fields)
	if len(names) == 0 {
		return "{}\n"
	}
	var b strings.Builder
	b.WriteString("{\n")
	for i, name := range names {
		key, _ := json.Marshal(name)
		fmt.Fprintf(&b, "  %s: %s", string(key), normalizeJSONLiteral(group.Fields[name]))
		if i < len(names)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func proofPatchSurfaceExportTOML(group proofPatchSurfaceExport) string {
	names := sortedMapKeys(group.Fields)
	var b strings.Builder
	b.WriteString("# Ariadne suggested proof evidence. Review before applying.\n")
	for _, name := range names {
		fmt.Fprintf(&b, "%s = %s\n", name, normalizeJSONLiteral(group.Fields[name]))
	}
	return b.String()
}

func proofPatchSurfaceExportMarkdown(group proofPatchSurfaceExport) string {
	names := sortedMapKeys(group.Fields)
	var b strings.Builder
	b.WriteString("<!-- Ariadne suggested proof evidence. Review before applying. -->\n")
	for _, name := range names {
		fmt.Fprintf(&b, "- %s: %s\n", name, normalizeJSONLiteral(group.Fields[name]))
	}
	return b.String()
}

func proofPatchExportReadme(plan model.ProofPlanReport, manifest proofPatchExportManifest) string {
	var b strings.Builder
	b.WriteString("# Ariadne Proof Patch Export\n\n")
	b.WriteString("These files are suggested parser-recognized evidence artifacts. Review them before copying into the scanned repo or endpoint configuration.\n\n")
	fmt.Fprintf(&b, "- Case filter: %s\n", firstNonEmpty(plan.CaseFilter, "all"))
	fmt.Fprintf(&b, "- Proof patches: %d\n", manifest.PatchCount)
	fmt.Fprintf(&b, "- Generated files: %d\n\n", len(manifest.Files))
	if len(manifest.ClosureControls) > 0 || len(manifest.ClosureFiles) > 0 || manifest.ClosureRule != "" {
		b.WriteString("## Closure Bundle\n\n")
		if len(manifest.ClosureControls) > 0 {
			fmt.Fprintf(&b, "- Controls: `%s`\n", strings.Join(manifest.ClosureControls, "`, `"))
		}
		if len(manifest.ClosureFiles) > 0 {
			fmt.Fprintf(&b, "- Generated files: `%s`\n", strings.Join(manifest.ClosureFiles, "`, `"))
		}
		if manifest.ClosureRule != "" {
			fmt.Fprintf(&b, "- Rule: %s\n", manifest.ClosureRule)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Files\n\n")
	for _, file := range manifest.Files {
		fmt.Fprintf(&b, "- `%s` for `%s` (%s)\n", file.Path, file.Surface, file.Format)
		if file.DestinationPath != "" {
			fmt.Fprintf(&b, "  - Suggested destination: `%s`\n", file.DestinationPath)
		}
		if file.ApplyCommand != "" {
			fmt.Fprintf(&b, "  - Review/apply command: `%s`\n", file.ApplyCommand)
		}
	}
	if len(manifest.Workflow) > 0 {
		b.WriteString("\n## Workflow\n\n")
		for i, step := range manifest.Workflow {
			fmt.Fprintf(&b, "%d. **%s**: %s\n", i+1, firstNonEmpty(step.Title, step.ID), step.Summary)
			for _, command := range limitStrings(step.Commands, 4) {
				fmt.Fprintf(&b, "   - `%s`\n", command)
			}
		}
	}
	b.WriteString("\n## Verification\n\n")
	for _, command := range limitStrings(plan.RerunCommands, 4) {
		fmt.Fprintf(&b, "- `%s`\n", command)
	}
	for _, command := range limitStrings(plan.CompareCommands, 4) {
		fmt.Fprintf(&b, "- `%s`\n", command)
	}
	b.WriteString("\n## Limitations\n\n")
	for _, limitation := range limitStrings(manifest.Limitations, 8) {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	return b.String()
}

func proofPatchExportSurfaceRelPath(surface string) string {
	surface = strings.TrimSpace(surface)
	if surface == "" || strings.Contains(surface, "supported control evidence") {
		return filepath.Join("surfaces", "supported-control-evidence.txt")
	}
	cleaned := filepath.ToSlash(filepath.Clean(surface))
	cleaned = strings.TrimPrefix(cleaned, "/")
	cleaned = strings.TrimPrefix(cleaned, "./")
	for strings.HasPrefix(cleaned, "../") {
		cleaned = strings.TrimPrefix(cleaned, "../")
	}
	cleaned = strings.ReplaceAll(cleaned, ":", "_")
	if cleaned == "" || cleaned == "." || cleaned == ".." {
		cleaned = "supported-control-evidence.txt"
	}
	return filepath.FromSlash(filepath.Join("surfaces", cleaned))
}

func proofPatchSuggestedDestinationPath(targetPath, surface string) string {
	surface = strings.TrimSpace(surface)
	if surface == "" || strings.Contains(surface, "supported control evidence") {
		return ""
	}
	if filepath.IsAbs(surface) {
		return filepath.Clean(surface)
	}
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" {
		return surface
	}
	return filepath.Clean(filepath.Join(targetPath, surface))
}

func proofPatchApplyCommand(exportDir, relPath, destinationPath string) string {
	exportDir = strings.TrimSpace(exportDir)
	relPath = strings.TrimSpace(relPath)
	destinationPath = strings.TrimSpace(destinationPath)
	if exportDir == "" || relPath == "" || destinationPath == "" {
		return ""
	}
	destinationDir := filepath.Dir(destinationPath)
	return fmt.Sprintf("cd %s && mkdir -p %s && cp %s %s", shellQuoteCommandArg(exportDir), shellQuoteCommandArg(destinationDir), shellQuoteCommandArg(relPath), shellQuoteCommandArg(destinationPath))
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func normalizeJSONLiteral(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "true"
	}
	if json.Valid([]byte(value)) {
		return value
	}
	blob, _ := json.Marshal(value)
	return string(blob)
}
