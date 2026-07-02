package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

func buildAssessSourceReferenceWorkbench(root string, packet model.AssessOperatorPacket, workbench model.AssessOperatorWorkbench, decision model.AssessDecision, quality model.AssessSignalQuality, triage model.AssessTriage, action model.AssessFirstAction, topCases []model.ControlOperatorCase) model.AssessSourceReferences {
	var refs []model.EvidenceReference
	refs = append(refs, packet.EvidenceToOpen...)
	refs = append(refs, workbench.EvidenceToOpen...)
	refs = append(refs, decision.EvidenceReferences...)
	refs = append(refs, quality.EvidenceReferences...)
	refs = append(refs, triage.EvidenceReferences...)
	refs = append(refs, action.EvidenceReferences...)
	refs = append(refs, action.CurrentAction.EvidenceReferences...)
	if len(topCases) > 0 {
		refs = append(refs, topCases[0].EvidenceReferences...)
	}
	proofSurfaces := assessSourceReferenceProofSurfaces(packet, workbench, decision, action)
	controls := assessSourceReferenceControls(packet, workbench, decision, action)
	return buildAssessSourceReferencesFromRefs(root, refs, proofSurfaces, controls)
}

func buildAssessSourceReferencesFromRefs(root string, refs []model.EvidenceReference, proofSurfaces []string, controls []string) model.AssessSourceReferences {
	refs = rankEvidenceReferencesForOperator(refs)
	rows := buildAssessSourceReferenceRows(root, refs)
	out := model.AssessSourceReferences{
		Available:          len(rows) > 0,
		EvidenceReferences: refs,
		Rows:               rows,
		ActionBoard:        buildAssessSourceActionBoard(root, rows, proofSurfaces, controls),
		Limitations: []string{
			"Source references are deterministic evidence pointers. They do not prove live runtime enforcement by themselves.",
			"Private, history, transcript, paste, and cache surfaces use metadata-only inspect commands by default.",
		},
	}
	for _, row := range rows {
		if row.LocalFile {
			out.LocalFiles++
		}
		if row.MetadataOnly {
			out.MetadataOnly++
		} else if row.LocalFile {
			out.ContentInspectable++
		}
	}
	if len(rows) > 0 {
		out.Summary = fmt.Sprintf("%d source-backed evidence reference(s), %d local file(s), %d content-inspectable file(s), %d metadata-only private/context surface(s).",
			len(rows),
			out.LocalFiles,
			out.ContentInspectable,
			out.MetadataOnly,
		)
	}
	return out
}

func assessSourceReferenceProofSurfaces(packet model.AssessOperatorPacket, workbench model.AssessOperatorWorkbench, decision model.AssessDecision, action model.AssessFirstAction) []string {
	var values []string
	values = append(values, packet.ProofSurface)
	values = append(values, workbench.Proof.Surface)
	values = append(values, workbench.Runbook.ProofSurface)
	values = append(values, decision.CurrentProofSurface, decision.ProofSurface)
	values = append(values, decision.SuggestedDestination)
	values = append(values, decision.SuggestedDestinations...)
	values = append(values, action.CurrentAction.Surface, action.CurrentAction.SuggestedDestination)
	return uniqueStrings(nonEmptyStrings(values...))
}

func assessSourceReferenceControls(packet model.AssessOperatorPacket, workbench model.AssessOperatorWorkbench, decision model.AssessDecision, action model.AssessFirstAction) []string {
	var values []string
	values = append(values, packet.CurrentControl)
	values = append(values, packet.TargetControls...)
	values = append(values, packet.MissingControls...)
	values = append(values, workbench.Proof.Control)
	values = append(values, workbench.Proof.Controls...)
	values = append(values, workbench.Runbook.CurrentControl)
	values = append(values, decision.CurrentControl)
	values = append(values, decision.MissingHardBarriers...)
	values = append(values, action.StartingControls...)
	values = append(values, action.CurrentAction.Control)
	return uniqueStrings(nonEmptyStrings(values...))
}

func buildAssessSourceReferenceRows(root string, refs []model.EvidenceReference) []model.AssessSourceRefRow {
	refs = rankEvidenceReferencesForOperator(refs)
	rows := make([]model.AssessSourceRefRow, 0, len(refs))
	for _, ref := range refs {
		source := firstNonEmpty(ref.Source, ref.ID, ref.Kind)
		if strings.TrimSpace(source) == "" {
			continue
		}
		localPath := sourceReferenceLocalPath(root, ref)
		metadataOnly := sourceReferenceMetadataOnly(ref)
		rows = append(rows, model.AssessSourceRefRow{
			Source:         source,
			DisplaySource:  evidenceReferenceSourceLabel(source, ref),
			Line:           sourceReferenceLineLabel(ref),
			Kind:           ref.Kind,
			Fact:           ref.Summary,
			LocalPath:      localPath,
			LocalFile:      localPath != "",
			MetadataOnly:   metadataOnly,
			InspectCommand: sourceReferenceInspectCommand(root, ref),
		})
	}
	return rows
}

func buildAssessSourceActionBoard(root string, rows []model.AssessSourceRefRow, proofSurfaces []string, controls []string) []model.AssessSourceAction {
	actions := make([]model.AssessSourceAction, 0, len(rows)+len(proofSurfaces))
	index := map[string]int{}
	for _, row := range rows {
		key := sourceActionKey(row.Source, row.LocalPath)
		if key == "" {
			continue
		}
		pos, ok := index[key]
		if !ok {
			action := model.AssessSourceAction{
				Source:            row.Source,
				DisplaySource:     firstNonEmpty(row.DisplaySource, row.Source),
				Role:              "evidence",
				ActionKind:        sourceActionKind(row),
				RecommendedAction: sourceActionRecommendation(row),
				LocalPath:         row.LocalPath,
				LocalFile:         row.LocalFile,
				MetadataOnly:      row.MetadataOnly,
				LineLabels:        []string{},
				Kinds:             []string{},
				Facts:             []string{},
				InspectCommands:   []string{},
				RelatedControls:   []string{},
			}
			actions = append(actions, action)
			pos = len(actions) - 1
			index[key] = pos
		}
		action := actions[pos]
		action.MetadataOnly = action.MetadataOnly || row.MetadataOnly
		action.LineLabels = uniqueStrings(append(action.LineLabels, row.Line))
		action.Kinds = uniqueStrings(append(action.Kinds, row.Kind))
		action.Facts = uniqueStrings(append(action.Facts, row.Fact))
		action.InspectCommands = uniqueStrings(append(action.InspectCommands, sourceActionInspectCommand(row, action.ActionKind)))
		if action.MetadataOnly {
			action.ActionKind = "inspect_metadata_only"
			action.RecommendedAction = "Inspect metadata only. Do not dump private history, cache, transcript, or paste contents by default."
		}
		actions[pos] = action
	}
	for _, surface := range proofSurfaces {
		surface = strings.TrimSpace(surface)
		if surface == "" {
			continue
		}
		localPath := dashboardFilePath(root, surface)
		key := "proof|" + firstNonEmpty(localPath, surface)
		if _, ok := index[key]; ok {
			continue
		}
		relatedControls := sourceProofSurfaceControls(surface, controls)
		actions = append(actions, model.AssessSourceAction{
			Source:            surface,
			DisplaySource:     surface,
			Role:              "proof_surface",
			ActionKind:        "add_or_verify_control",
			RecommendedAction: sourceProofSurfaceRecommendation(relatedControls),
			LocalPath:         localPath,
			LocalFile:         localPath != "",
			MetadataOnly:      false,
			LineLabels:        []string{"not applicable"},
			Kinds:             []string{"proof_surface"},
			Facts:             []string{"Ariadne expects control evidence here for the current closure loop."},
			InspectCommands:   proofSurfaceInspectCommands(localPath),
			RelatedControls:   relatedControls,
		})
		index[key] = len(actions) - 1
	}
	if len(actions) == 0 {
		return []model.AssessSourceAction{}
	}
	return rankAssessSourceActions(actions)
}

func rankAssessSourceActions(actions []model.AssessSourceAction) []model.AssessSourceAction {
	out := append([]model.AssessSourceAction{}, actions...)
	sort.SliceStable(out, func(i, j int) bool {
		left := sourceActionPriority(out[i])
		right := sourceActionPriority(out[j])
		return left < right
	})
	return out
}

func sourceActionPriority(action model.AssessSourceAction) int {
	kind := strings.ToLower(strings.TrimSpace(action.ActionKind))
	role := strings.ToLower(strings.TrimSpace(action.Role))
	score := 50
	switch {
	case role == "proof_surface" || kind == "add_or_verify_control":
		score = 0
	case kind == "verify_control":
		score = 5
	case kind == "confirm_boundary":
		score = 10
	case kind == "inspect_risk_source":
		score = 20
	case kind == "inspect_evidence":
		score = 30
	case kind == "reference_fact":
		score = 40
	}
	if action.MetadataOnly {
		score += 70
	}
	if !action.LocalFile {
		score += 5
	}
	return score
}

func sourceActionKey(source, localPath string) string {
	if localPath != "" {
		return "local|" + localPath
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	return "source|" + source
}

func sourceActionKind(row model.AssessSourceRefRow) string {
	if row.MetadataOnly {
		return "inspect_metadata_only"
	}
	if !row.LocalFile {
		return "reference_fact"
	}
	kind := strings.ToLower(row.Kind)
	fact := strings.ToLower(row.Fact)
	switch {
	case kind == "boundary" || strings.Contains(fact, "secret-like") || strings.Contains(fact, "sensitive"):
		return "confirm_boundary"
	case kind == "control" || strings.Contains(fact, "control"):
		return "verify_control"
	case kind == "authority" || kind == "tool" || kind == "trust_input" || kind == "trust-input" || kind == "runtime":
		return "inspect_risk_source"
	default:
		return "inspect_evidence"
	}
}

func sourceActionInspectCommand(row model.AssessSourceRefRow, actionKind string) string {
	if actionKind == "confirm_boundary" && row.LocalPath != "" {
		quoted := shellQuoteCommandArg(row.LocalPath)
		source := firstNonEmpty(row.DisplaySource, row.Source, row.LocalPath)
		present := shellQuoteCommandArg("sensitive boundary path exists: " + source)
		missing := shellQuoteCommandArg("sensitive boundary path not found: " + source)
		return fmt.Sprintf("test -e %s && echo %s || echo %s", quoted, present, missing)
	}
	return row.InspectCommand
}

func sourceActionRecommendation(row model.AssessSourceRefRow) string {
	switch sourceActionKind(row) {
	case "inspect_metadata_only":
		return "Inspect metadata only. Do not dump private history, cache, transcript, or paste contents by default."
	case "confirm_boundary":
		return "Confirm the sensitive boundary signal without exposing values; this file explains what Ariadne is protecting."
	case "verify_control":
		return "Verify the declared control exists and is enforced, then rerun Ariadne to confirm the graph path changed."
	case "inspect_risk_source":
		return "Inspect this source to confirm the exact authority, tool, runtime, or trust input Ariadne used in the graph."
	case "reference_fact":
		return "Use this modeled or internal fact to understand the graph path; there is no local file to open."
	default:
		return "Inspect this deterministic evidence row before changing controls."
	}
}

func sourceProofSurfaceRecommendation(controls []string) string {
	control := firstString(controls)
	if control == "" {
		return "Add or verify parser-recognized control evidence here, then rerun and compare Ariadne output."
	}
	return "Add or verify parser-recognized evidence for " + control + " here, then rerun and compare Ariadne output."
}

func sourceProofSurfaceControls(surface string, controls []string) []string {
	surface = strings.ToLower(strings.TrimSpace(surface))
	if len(controls) == 0 {
		return []string{}
	}
	var filtered []string
	for _, control := range controls {
		lower := strings.ToLower(control)
		switch {
		case strings.Contains(surface, "egress-policy"):
			if strings.Contains(lower, "egress") || strings.Contains(lower, "network") || strings.Contains(lower, "webhook") || strings.Contains(lower, "per-tool-network") {
				filtered = append(filtered, control)
			}
		case strings.Contains(surface, "output-policy"):
			if strings.Contains(lower, "output") {
				filtered = append(filtered, control)
			}
		case strings.Contains(surface, "input-policy"):
			if strings.Contains(lower, "input") || strings.Contains(lower, "trusted-source") || strings.Contains(lower, "prompt") {
				filtered = append(filtered, control)
			}
		case strings.Contains(surface, "tool-policy"):
			if strings.Contains(lower, "tool") || strings.Contains(lower, "mcp") || strings.Contains(lower, "artifact") {
				filtered = append(filtered, control)
			}
		case strings.Contains(surface, "identity-policy"):
			if strings.Contains(lower, "identity") || strings.Contains(lower, "credential") || strings.Contains(lower, "jit") || strings.Contains(lower, "token") {
				filtered = append(filtered, control)
			}
		default:
			filtered = append(filtered, control)
		}
	}
	if len(filtered) == 0 {
		return controls
	}
	return uniqueStrings(filtered)
}

func proofSurfaceInspectCommands(localPath string) []string {
	if localPath == "" {
		return []string{}
	}
	quoted := shellQuoteCommandArg(localPath)
	message := shellQuoteCommandArg("proof surface not present yet: " + localPath)
	return []string{
		fmt.Sprintf("test -f %s && sed -n '1,160p' %s || echo %s", quoted, quoted, message),
	}
}

func sourceReferenceLineLabel(ref model.EvidenceReference) string {
	if ref.LineStart <= 0 {
		return "not recorded"
	}
	if ref.LineEnd > ref.LineStart {
		return fmt.Sprintf("%d-%d", ref.LineStart, ref.LineEnd)
	}
	return fmt.Sprintf("%d", ref.LineStart)
}

func sourceReferenceInspectCommand(root string, ref model.EvidenceReference) string {
	path := sourceReferenceLocalPath(root, ref)
	if path == "" {
		return ""
	}
	if sourceReferenceMetadataOnly(ref) {
		return fmt.Sprintf("ls -ld %s", shellQuoteCommandArg(path))
	}
	if ref.LineStart > 0 {
		lineEnd := ref.LineEnd
		if lineEnd < ref.LineStart {
			lineEnd = ref.LineStart
		}
		return fmt.Sprintf("sed -n '%d,%dp' %s", ref.LineStart, lineEnd, shellQuoteCommandArg(path))
	}
	return fmt.Sprintf("sed -n '1,160p' %s", shellQuoteCommandArg(path))
}

func sourceReferenceLocalPath(root string, ref model.EvidenceReference) string {
	source := firstNonEmpty(ref.Source, ref.ID, ref.Kind)
	return dashboardFilePath(root, source)
}

func sourceReferenceMetadataOnly(ref model.EvidenceReference) bool {
	value := strings.ToLower(strings.TrimSpace(ref.Source + " " + ref.Kind + " " + ref.Summary))
	return strings.Contains(value, "history") ||
		strings.Contains(value, "cache") ||
		strings.Contains(value, "paste") ||
		strings.Contains(value, "transcript") ||
		strings.Contains(value, "private context") ||
		strings.Contains(value, "high-volume") ||
		strings.Contains(value, "approx bytes") ||
		strings.Contains(value, "contents were not inspected") ||
		strings.Contains(value, "contents are not inspected") ||
		strings.Contains(value, "contents are not emitted") ||
		strings.Contains(value, "contents were not emitted")
}
