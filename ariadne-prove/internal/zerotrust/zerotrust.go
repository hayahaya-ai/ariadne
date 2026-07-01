package zerotrust

import (
	"fmt"
	"sort"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

const FrameworkVersion = "ariadne.zero_trust_agent/v1"

func Assess(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrust {
	checks := []model.ZeroTrustCheck{
		influenceBoundary(c, g, exposures),
		authorityBoundary(c, g, exposures),
		sensitiveBoundary(c, g, exposures),
		toolBoundary(c, g, exposures),
		memoryBoundary(c, g),
		identityBoundary(c, g),
		observabilityBoundary(c),
		controlStrengthBoundary(c, g, exposures),
	}
	for i := range checks {
		checks[i] = normalizeCheck(checks[i])
	}
	return model.ZeroTrust{
		FrameworkVersion: FrameworkVersion,
		Summary:          summarize(checks),
		Checks:           checks,
	}
}

func influenceBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	inputs := trustInputEvidence(c, true)
	status := model.ZeroTrustNotObserved
	finding := "No risky untrusted instruction surface was observed by supported collectors."
	if len(c.TrustInputs) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Instruction surfaces exist; Ariadne did not prove runtime input isolation."
	}
	if len(inputs) > 0 {
		status = statusForExposures(exposures, "prompt-injection-to-secret-canary", "data-egress-chain")
		finding = "Risky instruction input can influence an agent runtime."
		if status == model.ZeroTrustBreaking {
			finding = "Risky instruction input influences an agent runtime that has an unbroken exposure path."
		}
		if status == model.ZeroTrustControlled {
			finding = "Risky instruction input exists, but a graph control breaks the supported exposure path."
		}
	}
	return model.ZeroTrustCheck{
		ID:         "zt:influence-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "Influence boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Untrusted natural-language inputs should not directly steer authority without a verifiable break-path control.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(inputs, trustInputEvidence(c, false)), 8),
		GraphEdges: edgesForTypes(g, "influences"),
		Controls:   controlsForExposures(exposures, "prompt-injection-to-secret-canary", "data-egress-chain"),
		Actions: []string{
			"Keep repo and memory instructions outside broad endpoint authority where possible.",
			"Require explicit controls before untrusted instructions can reach file, tool, or network authority.",
		},
	}
}

func authorityBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	status := model.ZeroTrustNotObserved
	finding := "No supported agent authority was modeled."
	if len(c.Authorities) > 0 {
		status = statusForAnyExposure(exposures)
		finding = "Agent authority exists; Ariadne could not prove whether it is least-agency scoped."
		if status == model.ZeroTrustBreaking {
			finding = "Agent authority reaches a sensitive boundary without an observed break-path control."
		}
		if status == model.ZeroTrustControlled {
			finding = "Agent authority exists, but controls restrict the supported exposure path."
		}
	}
	return model.ZeroTrustCheck{
		ID:         "zt:authority-boundary",
		Principle:  "Least agency",
		Boundary:   "Authority boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "The agent should have only the authority needed for the task; broad authority should be removed, not merely warned about.",
		Finding:    finding,
		Evidence:   limitEvidence(authorityEvidence(c), 8),
		GraphEdges: edgesForTypes(g, "has_authority", "reaches"),
		Controls:   controlsForExposures(exposures),
		Actions: []string{
			"Constrain filesystem, shell, network, and MCP authority to the smallest useful scope.",
			"Prefer deny-by-default permission posture with explicit allowlists for necessary tools.",
		},
	}
}

func sensitiveBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	evidence := boundaryEvidence(c, "boundary:secret-like-file", "boundary:developer-secret-boundary", "boundary:agent-private-context", "boundary:external-destination")
	status := model.ZeroTrustNotObserved
	finding := "No supported sensitive boundary was modeled."
	if len(evidence) > 0 {
		status = statusForExposures(exposures, "prompt-injection-to-secret-canary", "data-egress-chain")
		finding = "Sensitive boundaries exist; Ariadne did not prove whether all reachable paths are controlled."
		if status == model.ZeroTrustBreaking {
			finding = "A supported graph path reaches a sensitive boundary without an observed break-path control."
		}
		if status == model.ZeroTrustControlled {
			finding = "A sensitive boundary was modeled, and Ariadne found a control edge that breaks the supported path."
		}
	}
	return model.ZeroTrustCheck{
		ID:         "zt:sensitive-boundary",
		Principle:  "Assume breach",
		Boundary:   "Sensitive data boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Compromise of one agent path should not expose developer secrets, private context, or external data movement.",
		Finding:    finding,
		Evidence:   limitEvidence(evidence, 8),
		GraphEdges: edgesForTypes(g, "reaches", "restricts"),
		Controls:   controlsForExposures(exposures, "prompt-injection-to-secret-canary", "data-egress-chain"),
		Actions: []string{
			"Add deny-read controls for secret-like paths, credential stores, and private agent context.",
			"Separate private-data reachability from external communication reachability.",
		},
	}
}

func toolBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	status := model.ZeroTrustNotObserved
	finding := "No supported agent-callable tool or MCP surface was modeled."
	if len(c.Tools) > 0 {
		status = statusForExposures(exposures, "mutable-tool-launch-execution", "data-egress-chain")
		finding = "Agent-callable tool surfaces exist; Ariadne could not prove all tool authority is reviewed and scoped."
		if status == model.ZeroTrustBreaking {
			finding = "Agent-callable tool configuration can bridge model behavior to execution or external communication without an observed break-path control."
		}
		if status == model.ZeroTrustControlled {
			finding = "Agent-callable tool configuration exists, and Ariadne found review, pinning, or reachability controls."
		}
	}
	return model.ZeroTrustCheck{
		ID:         "zt:tool-boundary",
		Principle:  "Least agency",
		Boundary:   "Tool and MCP boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Tools should be allowlisted, pinned, and scoped so the agent cannot gain new capability through mutable launch paths.",
		Finding:    finding,
		Evidence:   limitEvidence(toolEvidence(c), 8),
		GraphEdges: edgesForTypes(g, "can_call", "grants", "restricts"),
		Controls:   controlsForExposures(exposures, "mutable-tool-launch-execution", "data-egress-chain"),
		Actions: []string{
			"Review MCP servers and plugin/tool configs as authority-bearing surfaces.",
			"Pin package-manager launchers and remove unused model-callable tools.",
		},
	}
}

func memoryBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	evidence := memoryEvidence(c)
	status := model.ZeroTrustNotObserved
	finding := "No supported memory, history, paste cache, or private context surface was observed."
	edges := edgesForNode(g, "boundary:agent-private-context")
	controls := []string{}
	if len(evidence) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Private context surfaces exist; Ariadne summarizes them but does not validate memory isolation or integrity."
		controls = controlIDs(c, "control:deny-secret-read")
		if hasEdge(g, "authority:file-read|reaches|boundary:agent-private-context") || hasEdge(g, "authority:broad-local|reaches|boundary:agent-private-context") {
			status = model.ZeroTrustBreaking
			finding = "Agent authority reaches private context or history surfaces without an observed memory isolation control."
		}
		if hasEdge(g, "control:deny-secret-read|restricts|boundary:agent-private-context") {
			status = model.ZeroTrustControlled
			finding = "Private context surfaces exist, and a deny-read control restricts the modeled private-context boundary."
		}
	}
	return model.ZeroTrustCheck{
		ID:         "zt:memory-boundary",
		Principle:  "Assume breach",
		Boundary:   "Memory and context boundary",
		Tier:       "enterprise",
		Status:     status,
		DesignTest: "Persisted context should be isolated, bounded by retention, and protected from authority paths that do not need it.",
		Finding:    finding,
		Evidence:   limitEvidence(evidence, 8),
		GraphEdges: edges,
		Controls:   controls,
		Actions: []string{
			"Keep histories, paste caches, and memory stores outside broad agent-readable roots.",
			"Define retention and isolation controls for persisted agent context.",
		},
		Limitations: []string{"Ariadne summarizes private context metadata only; it does not inspect private history contents by default."},
	}
}

func identityBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	status := model.ZeroTrustNotObserved
	finding := "No supported agent runtime or authority was observed."
	credentialBoundary := boundaryEvidence(c, "boundary:credential-material")
	identityControls := controlsEvidence(c, "control:credential-helper", "control:short-lived-credential")
	evidence := limitEvidence(firstEvidence(append(credentialBoundary, identityControls...), runtimeEvidence(c), authorityEvidence(c), toolEvidence(c)), 8)
	if len(c.Runtimes) > 0 || len(c.Authorities) > 0 || len(c.Tools) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Agent runtime or authority exists, but Ariadne did not collect evidence for per-agent identity, short-lived credentials, or JIT access."
	}
	if len(identityControls) > 0 && len(credentialBoundary) == 0 {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed credential helper, short-lived credential, or federated identity controls for agent authentication."
	}
	if len(credentialBoundary) > 0 {
		status = model.ZeroTrustBreaking
		finding = "Ariadne observed inline credential material indicators in agent configuration, which breaks scoped credential isolation."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:identity-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "Agent identity boundary",
		Tier:       "enterprise",
		Status:     status,
		DesignTest: "Agent actions should be attributable to scoped identities with expiring credentials, not inherited standing user authority.",
		Finding:    finding,
		Evidence:   evidence,
		GraphEdges: edgesForTypes(g, "configures", "has_authority", "can_call"),
		Controls:   controlIDs(c, "control:credential-helper", "control:short-lived-credential"),
		Actions: []string{
			"Prefer per-agent identities, short-lived credentials, and auditable credential issuance.",
			"Treat shared local user authority as an unknown until identity evidence is collected.",
		},
		Limitations: []string{"Ariadne detects declared credential helpers and federated identity indicators, but does not validate token lifetime, identity provider policy, JIT authorization, ABAC, or hardware binding."},
	}
}

func observabilityBoundary(c model.Collection) model.ZeroTrustCheck {
	status := model.ZeroTrustNotObserved
	finding := "No supported agent runtime, tool, or authority was observed."
	auditControls := controlsEvidence(c, "control:audit-logging")
	evidence := limitEvidence(firstEvidence(auditControls, surfaceEvidenceByCategory(c, "history-cache"), runtimeEvidence(c), toolEvidence(c)), 8)
	if len(c.Runtimes) > 0 || len(c.Tools) > 0 || len(c.Authorities) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed agent surfaces, but did not verify tamper-resistant action logs, approval logs, or end-to-end tool-call auditability."
	}
	if len(surfaceEvidenceByCategory(c, "history-cache")) > 0 {
		finding = "Local history or cache surfaces exist, but Ariadne treats them as private context, not as verified audit trails."
	}
	if len(auditControls) > 0 {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed declared tool-call, approval, telemetry, or audit logging controls."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:observability-boundary",
		Principle:  "Assume breach",
		Boundary:   "Observability boundary",
		Tier:       "enterprise",
		Status:     status,
		DesignTest: "A team should be able to reconstruct what the agent did, why, and which approval or policy allowed it.",
		Finding:    finding,
		Evidence:   evidence,
		Controls:   controlIDs(c, "control:audit-logging"),
		Actions: []string{
			"Collect tool-call, approval, credential, and network audit evidence for agent sessions.",
			"Measure whether critical agent behavior would be visible quickly enough for a human to act.",
		},
		Limitations: []string{"Ariadne detects declared audit and telemetry controls, but does not yet ingest live telemetry, SIEM data, or tamper-resistant log proofs."},
	}
}

func controlStrengthBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	status := model.ZeroTrustNotObserved
	finding := "No supported exposure path or break-path control was observed."
	if len(exposures) > 0 {
		status = controlStrengthStatus(exposures)
		finding = "Supported paths were inconclusive; Ariadne could not prove whether controls remove capability."
		if status == model.ZeroTrustBreaking {
			finding = "At least one supported exposure path is unbroken; no observed control removes the capability along that path."
		}
		if status == model.ZeroTrustControlled {
			finding = "Supported exposure paths are broken by observed control edges that remove or restrict the capability."
		}
	}
	return model.ZeroTrustCheck{
		ID:         "zt:control-strength",
		Principle:  "Impossible, not tedious",
		Boundary:   "Control boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Controls should remove the path or authority, not merely add friction an automated attacker can grind through.",
		Finding:    finding,
		Evidence:   limitEvidence(controlEvidence(c), 8),
		GraphEdges: edgesForTypes(g, "restricts"),
		Controls:   controlsForExposures(exposures),
		Actions: []string{
			"Prefer controls that remove authority: deny-read, network isolation, sandboxing, allowlists, and pinned tool launchers.",
			"Treat warnings, prompts, or rate limits as insufficient unless they create a graph break.",
		},
	}
}

func summarize(checks []model.ZeroTrustCheck) model.ZeroTrustSummary {
	var summary model.ZeroTrustSummary
	summary.Total = len(checks)
	for _, check := range checks {
		switch check.Status {
		case model.ZeroTrustBreaking:
			summary.Breaking++
		case model.ZeroTrustControlled:
			summary.Controlled++
		case model.ZeroTrustUnknown:
			summary.Unknown++
		default:
			summary.NotObserved++
		}
	}
	return summary
}

func normalizeCheck(check model.ZeroTrustCheck) model.ZeroTrustCheck {
	if check.Evidence == nil {
		check.Evidence = []model.ZeroTrustEvidence{}
	}
	if check.GraphEdges == nil {
		check.GraphEdges = []string{}
	}
	if check.Actions == nil {
		check.Actions = []string{}
	}
	if check.Controls == nil {
		check.Controls = []string{}
	}
	if check.Limitations == nil {
		check.Limitations = []string{}
	}
	return check
}

func statusForAnyExposure(exposures []model.ExposureResult) model.ZeroTrustStatus {
	return statusForExposures(exposures)
}

func statusForExposures(exposures []model.ExposureResult, ids ...string) model.ZeroTrustStatus {
	allow := map[string]bool{}
	for _, id := range ids {
		allow[id] = true
	}
	seen := false
	controlled := false
	unknown := false
	for _, exposure := range exposures {
		if len(allow) > 0 && !allow[exposure.ID] {
			continue
		}
		seen = true
		switch exposure.Status {
		case model.StatusExposed:
			return model.ZeroTrustBreaking
		case model.StatusProtected:
			controlled = true
		default:
			unknown = true
		}
	}
	if controlled && !unknown {
		return model.ZeroTrustControlled
	}
	if unknown || seen {
		return model.ZeroTrustUnknown
	}
	return model.ZeroTrustNotObserved
}

func controlStrengthStatus(exposures []model.ExposureResult) model.ZeroTrustStatus {
	seen := false
	controlled := false
	unknown := false
	for _, exposure := range exposures {
		seen = true
		switch exposure.Status {
		case model.StatusExposed:
			return model.ZeroTrustBreaking
		case model.StatusProtected:
			controlled = true
		default:
			unknown = true
		}
	}
	if controlled {
		return model.ZeroTrustControlled
	}
	if unknown || seen {
		return model.ZeroTrustUnknown
	}
	return model.ZeroTrustNotObserved
}

func controlsForExposures(exposures []model.ExposureResult, ids ...string) []string {
	allow := map[string]bool{}
	for _, id := range ids {
		allow[id] = true
	}
	var out []string
	for _, exposure := range exposures {
		if len(allow) > 0 && !allow[exposure.ID] {
			continue
		}
		out = append(out, exposure.ControlsBreakPath...)
	}
	return uniqueStrings(out)
}

func controlIDs(c model.Collection, ids ...string) []string {
	allow := map[string]bool{}
	for _, id := range ids {
		allow[id] = true
	}
	var out []string
	for _, control := range c.Controls {
		if len(allow) == 0 || allow[control.ID] {
			out = append(out, control.ID)
		}
	}
	return uniqueStrings(out)
}

func trustInputEvidence(c model.Collection, riskyOnly bool) []model.ZeroTrustEvidence {
	var out []model.ZeroTrustEvidence
	for _, input := range c.TrustInputs {
		if riskyOnly && !input.Risky {
			continue
		}
		out = append(out, model.ZeroTrustEvidence{ID: input.ID, Kind: "trust_input", Source: input.Source, Summary: input.Summary})
	}
	return dedupeEvidence(out)
}

func runtimeEvidence(c model.Collection) []model.ZeroTrustEvidence {
	var out []model.ZeroTrustEvidence
	for _, runtime := range c.Runtimes {
		out = append(out, model.ZeroTrustEvidence{ID: runtime.ID, Kind: "runtime", Source: runtime.Source, Summary: runtime.Summary})
	}
	return dedupeEvidence(out)
}

func authorityEvidence(c model.Collection) []model.ZeroTrustEvidence {
	var out []model.ZeroTrustEvidence
	for _, authority := range c.Authorities {
		out = append(out, model.ZeroTrustEvidence{ID: authority.ID, Kind: "authority", Source: authority.Source, Summary: authority.Summary})
	}
	return dedupeEvidence(out)
}

func boundaryEvidence(c model.Collection, ids ...string) []model.ZeroTrustEvidence {
	allow := map[string]bool{}
	for _, id := range ids {
		allow[id] = true
	}
	var out []model.ZeroTrustEvidence
	for _, boundary := range c.Boundaries {
		if len(allow) > 0 && !allow[boundary.ID] {
			continue
		}
		out = append(out, model.ZeroTrustEvidence{ID: boundary.ID, Kind: "boundary", Source: boundary.Source, Summary: boundary.Summary})
	}
	return dedupeEvidence(out)
}

func toolEvidence(c model.Collection) []model.ZeroTrustEvidence {
	var out []model.ZeroTrustEvidence
	for _, tool := range c.Tools {
		out = append(out, model.ZeroTrustEvidence{ID: tool.ID, Kind: "tool", Source: tool.Source, Summary: tool.Summary})
	}
	return dedupeEvidence(out)
}

func controlEvidence(c model.Collection) []model.ZeroTrustEvidence {
	var out []model.ZeroTrustEvidence
	for _, control := range c.Controls {
		out = append(out, model.ZeroTrustEvidence{ID: control.ID, Kind: "control", Source: control.Source, Summary: control.Summary})
	}
	return dedupeEvidence(out)
}

func controlsEvidence(c model.Collection, ids ...string) []model.ZeroTrustEvidence {
	allow := map[string]bool{}
	for _, id := range ids {
		allow[id] = true
	}
	var out []model.ZeroTrustEvidence
	for _, control := range c.Controls {
		if len(allow) > 0 && !allow[control.ID] {
			continue
		}
		out = append(out, model.ZeroTrustEvidence{ID: control.ID, Kind: "control", Source: control.Source, Summary: control.Summary})
	}
	return dedupeEvidence(out)
}

func memoryEvidence(c model.Collection) []model.ZeroTrustEvidence {
	out := surfaceEvidenceByCategory(c, "memory")
	out = append(out, surfaceEvidenceByCategory(c, "history-cache")...)
	out = append(out, boundaryEvidence(c, "boundary:agent-private-context")...)
	return dedupeEvidence(out)
}

func surfaceEvidenceByCategory(c model.Collection, category string) []model.ZeroTrustEvidence {
	var out []model.ZeroTrustEvidence
	for _, surface := range c.Surfaces {
		if surface.Category != category {
			continue
		}
		summary := surface.Summary
		if surface.FileCount > 0 || surface.ApproxBytes > 0 {
			summary = fmt.Sprintf("%s Files: %d Approx bytes: %d.", summary, surface.FileCount, surface.ApproxBytes)
		}
		out = append(out, model.ZeroTrustEvidence{ID: surface.ID, Kind: surface.Category, Source: surface.Source, Summary: summary})
	}
	return dedupeEvidence(out)
}

func firstEvidence(groups ...[]model.ZeroTrustEvidence) []model.ZeroTrustEvidence {
	for _, group := range groups {
		if len(group) > 0 {
			return group
		}
	}
	return nil
}

func limitEvidence(values []model.ZeroTrustEvidence, limit int) []model.ZeroTrustEvidence {
	values = dedupeEvidence(values)
	if len(values) <= limit {
		return values
	}
	out := append([]model.ZeroTrustEvidence{}, values[:limit]...)
	out = append(out, model.ZeroTrustEvidence{ID: "evidence:omitted", Kind: "summary", Summary: fmt.Sprintf("%d additional evidence items omitted; use top-level evidence and graph arrays for the full set.", len(values)-limit)})
	return out
}

func dedupeEvidence(values []model.ZeroTrustEvidence) []model.ZeroTrustEvidence {
	seen := map[string]bool{}
	var out []model.ZeroTrustEvidence
	for _, value := range values {
		key := value.ID + "|" + value.Kind + "|" + value.Source + "|" + value.Summary
		if key == "|||" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			if out[i].ID == out[j].ID {
				return out[i].Source < out[j].Source
			}
			return out[i].ID < out[j].ID
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func edgesForTypes(g model.Graph, types ...string) []string {
	allow := map[string]bool{}
	for _, typ := range types {
		allow[typ] = true
	}
	var out []string
	for _, edge := range g.Edges {
		if allow[edge.Type] {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func edgesForNode(g model.Graph, nodeID string) []string {
	var out []string
	for _, edge := range g.Edges {
		if edge.From == nodeID || edge.To == nodeID {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func hasEdge(g model.Graph, key string) bool {
	for _, edge := range g.Edges {
		if edge.Key() == key {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
