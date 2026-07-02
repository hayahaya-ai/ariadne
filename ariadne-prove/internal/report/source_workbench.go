package report

import (
	"fmt"
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
	return buildAssessSourceReferencesFromRefs(root, refs)
}

func buildAssessSourceReferencesFromRefs(root string, refs []model.EvidenceReference) model.AssessSourceReferences {
	refs = rankEvidenceReferencesForOperator(refs)
	rows := buildAssessSourceReferenceRows(root, refs)
	out := model.AssessSourceReferences{
		Available:          len(rows) > 0,
		EvidenceReferences: refs,
		Rows:               rows,
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
