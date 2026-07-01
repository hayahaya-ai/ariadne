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
		egressBoundary(c, g, exposures),
		outputBoundary(c, g, exposures),
		toolBoundary(c, g, exposures),
		toolIntegrityBoundary(c, g),
		supplyChainBoundary(c, g),
		delegationBoundary(c, g),
		memoryBoundary(c, g),
		identityBoundary(c, g),
		workloadAuthorizationBoundary(c, g),
		continuousAuthorizationBoundary(c, g),
		approvalBoundary(c, g),
		resourceExhaustionBoundary(c, g),
		observabilityBoundary(c, g),
		responseBoundary(c, g, exposures),
		governanceBoundary(c, g),
		configIntegrityBoundary(c, g),
		controlStrengthBoundary(c, g, exposures),
	}
	for i := range checks {
		checks[i] = normalizeCheck(checks[i])
	}
	return model.ZeroTrust{
		FrameworkVersion: FrameworkVersion,
		Summary:          summarize(checks),
		Coverage:         coverage(checks),
		Maturity:         maturity(c),
		Checks:           checks,
	}
}

func influenceBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	inputs := trustInputEvidence(c, true)
	inputControls := controlsEvidence(c, inputControlIDs()...)
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
	if len(inputs) > 0 && hasHardInputControl(c) {
		status = model.ZeroTrustControlled
		finding = "Risky instruction input exists, and Ariadne observed input-isolation or trusted-source controls that break the influence path."
	}
	controls := controlIDs(c, inputControlIDs()...)
	return model.ZeroTrustCheck{
		ID:         "zt:influence-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "Influence boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Untrusted natural-language inputs should not directly steer authority without a verifiable break-path control.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(inputs, inputControls, trustInputEvidence(c, false)), 8),
		GraphEdges: edgesForTypes(g, "influences", "restricts"),
		Controls:   uniqueStrings(controls),
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
		hasBroadLocal := hasAuthority(c, "authority:broad-local")
		if hasBroadLocal {
			status = model.ZeroTrustBreaking
			finding = "Broad local authority was modeled; scoped controls do not satisfy least agency until broad standing authority is removed."
		} else if status == model.ZeroTrustBreaking {
			finding = "Agent authority reaches a sensitive boundary without an observed break-path control."
		}
		if status == model.ZeroTrustControlled {
			finding = "Agent authority exists, but controls restrict the supported exposure path."
		}
		if !hasBroadLocal && status != model.ZeroTrustBreaking && hasAnyControl(c, leastAgencyControlIDs()...) {
			status = model.ZeroTrustControlled
			finding = "Agent authority exists, and Ariadne observed scoped permission or deny-by-default controls for least-agency posture."
		}
	}
	controls := controlIDs(c, leastAgencyControlIDs()...)
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
		Controls:   uniqueStrings(controls),
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
		Controls:   controlIDs(c, sensitiveBoundaryControlIDs()...),
		Actions: []string{
			"Add deny-read controls for secret-like paths, credential stores, and private agent context.",
			"Separate private-data reachability from external communication reachability.",
		},
	}
}

func egressBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	controls := controlIDs(c, egressControlIDs()...)
	evidence := limitEvidence(firstEvidence(
		controlsEvidence(c, egressControlIDs()...),
		authorityEvidenceByID(c, "authority:external-communication", "authority:broad-local"),
		boundaryEvidence(c, "boundary:external-destination"),
	), 8)
	status := model.ZeroTrustNotObserved
	finding := "No supported external communication boundary was modeled."
	if hasAuthority(c, "authority:external-communication") || hasAuthority(c, "authority:broad-local") || hasBoundaryID(c, "boundary:external-destination") {
		status = model.ZeroTrustUnknown
		finding = "External communication reachability exists; Ariadne did not observe hard destination or per-tool network controls."
	}
	if hasAnyControl(c, softEgressControlIDs()...) && !hasAnyControl(c, hardEgressControlIDs()...) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed egress audit or output filtering evidence, but not a hard destination or network-scope boundary."
	}
	if statusForExposures(exposures, "data-egress-chain") == model.ZeroTrustBreaking {
		status = model.ZeroTrustBreaking
		finding = "Private-data reachability and external communication combine without an observed hard egress boundary."
	}
	if hasAnyControl(c, hardEgressControlIDs()...) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed hard egress boundary evidence such as network restriction, destination allowlist, webhook allowlist, or per-tool network scope."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:egress-boundary",
		Principle:  "Assume breach",
		Boundary:   "External egress boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Private data should not be able to leave through arbitrary external destinations; allowed destinations should be explicit and enforceable.",
		Finding:    finding,
		Evidence:   evidence,
		GraphEdges: edgesForNode(g, "boundary:external-destination"),
		Controls:   controls,
		Actions: []string{
			"Declare approved external destinations and webhook endpoints for agent runtimes.",
			"Scope network access per tool so private-data access and arbitrary outbound communication are not available in the same path.",
		},
		Limitations: []string{"Ariadne detects declared egress controls and graph reachability, but does not validate network enforcement, proxy policy, DNS policy, or runtime egress decisions."},
	}
}

func outputBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	controls := controlIDs(c, outputControlIDs()...)
	controlEvidence := controlsEvidence(c, outputControlIDs()...)
	riskEvidence := firstEvidence(
		boundaryEvidence(c, "boundary:secret-like-file", "boundary:developer-secret-boundary", "boundary:agent-private-context", "boundary:credential-material"),
		authorityEvidenceByID(c, "authority:file-read", "authority:broad-local"),
		trustInputEvidence(c, true),
	)
	status := model.ZeroTrustNotObserved
	finding := "No supported agent output or sensitive-output risk surface was observed."
	if hasOutputRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Agent output or sensitive boundary evidence exists, but Ariadne did not observe sensitive-output filtering, redaction, and logging controls."
	}
	if len(controlEvidence) > 0 && !hasHardOutputBoundary(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed output-control evidence, but not enough to prove sensitive-output filtering plus block/redaction plus logging."
	}
	if hasOutputLeakRisk(c, exposures) && !hasOutputBlockingControl(c) {
		status = model.ZeroTrustBreaking
		finding = "Sensitive agent output can be produced from reachable private data without observed filtering, redaction, and output-control logging evidence."
	}
	if hasOutputRelevantSurface(c) && hasHardOutputBoundary(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed hard output-control evidence: sensitive-output filtering, block or redaction, and logging before delivery."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:output-boundary",
		Principle:  "Assume breach",
		Boundary:   "Output controls boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Sensitive or harmful agent output should be blocked, redacted, reviewed, and logged before it reaches a user or external channel.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, riskEvidence), 8),
		GraphEdges: outputEdges(g),
		Controls:   controls,
		Actions: []string{
			"Declare output filtering for credentials, PII, and sensitive business data.",
			"Block or redact sensitive agent output before delivery, not only after external egress.",
			"Log output filtering and redaction decisions for later investigation.",
		},
		Limitations: []string{"Ariadne detects declared output-control policy and graph risk, but does not inspect live model responses, validate DLP enforcement, or perform semantic leakage testing."},
	}
}

func toolBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	status := model.ZeroTrustNotObserved
	finding := "No supported agent-callable tool or MCP surface was modeled."
	if hasToolIntegritySurface(c) {
		status = statusForExposures(exposures, "mutable-tool-launch-execution")
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
		Evidence:   limitEvidence(toolIntegrityEvidence(c), 8),
		GraphEdges: toolBoundaryEdges(g),
		Controls:   controlsForExposures(exposures, "mutable-tool-launch-execution"),
		Actions: []string{
			"Review MCP servers and plugin/tool configs as authority-bearing surfaces.",
			"Pin package-manager launchers and remove unused model-callable tools.",
		},
	}
}

func toolIntegrityBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	controls := controlIDs(c, toolIntegrityControlIDs()...)
	controlEvidence := controlsEvidence(c, toolIntegrityControlIDs()...)
	status := model.ZeroTrustNotObserved
	finding := "No supported agent-callable tool surface was observed."
	if hasToolIntegritySurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Agent-callable tool surfaces exist, but Ariadne did not observe hard tool provenance, descriptor integrity, authentication, or invocation validation evidence."
	}
	if len(controlEvidence) > 0 && hasToolIntegritySurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed tool security evidence, but not enough to prove a hard tool integrity boundary."
	}
	if hasRiskyToolSurface(c) && !hasHardToolIntegrity(c) {
		status = model.ZeroTrustBreaking
		finding = "Risk-bearing model-callable tool surfaces exist without observed hard provenance, allowlist, descriptor-integrity, authentication, or argument-validation controls."
	}
	if hasToolIntegritySurface(c) && hasHardToolIntegrity(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed hard tool integrity evidence such as allowlist plus pinning, signed deployment verification, descriptor validation, or authenticated short-lived tool access."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:tool-integrity-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "Tool integrity boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Model-callable tools should be approved, provenance-bound, descriptor-validated, authenticated, and argument-validated before they can extend agent capability.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, toolIntegrityEvidence(c)), 8),
		GraphEdges: toolIntegrityEdges(g),
		Controls:   controls,
		Actions: []string{
			"Maintain an approved tool and MCP server allowlist with pinned packages or signed artifacts.",
			"Validate tool descriptors, schemas, and arguments before tool calls execute.",
			"Require authenticated, short-lived tool access for sensitive or remote tools.",
		},
		Limitations: []string{"Ariadne detects declared tool integrity controls and static tool surfaces, but does not execute tools, resolve registries, validate signatures, inspect live MCP descriptors, or prove runtime enforcement."},
	}
}

func supplyChainBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	controls := controlIDs(c, supplyChainControlIDs()...)
	controlEvidence := controlsEvidence(c, supplyChainControlIDs()...)
	status := model.ZeroTrustNotObserved
	finding := "No supported tool, plugin, model, or AI supply-chain surface was observed."
	if hasSupplyChainRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Agent supply-chain surfaces exist, but Ariadne did not observe AI-BOM, model provenance, dependency health, provider review, signing, or runtime validation evidence."
	}
	if len(controlEvidence) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed supply-chain evidence, but not enough to prove BOM plus dependency health plus provenance or provider review plus artifact validation."
	}
	if hasRiskySupplyChainSurface(c) && !hasHardSupplyChainBoundary(c) {
		status = model.ZeroTrustBreaking
		finding = "Risk-bearing agent supply-chain surfaces exist without observed AI-BOM, provenance, dependency-health, provider-review, signing, or runtime-validation evidence."
	}
	if hasSupplyChainRelevantSurface(c) && hasHardSupplyChainBoundary(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed hard supply-chain evidence: AI-BOM, dependency health, provenance or provider review, and artifact signing or runtime validation."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:supply-chain-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "AI supply-chain boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Agent tool, framework, and model components should have known provenance, dependency health, provider review, and tamper-evident validation before they extend agent capability.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, supplyChainEvidence(c), toolIntegrityEvidence(c), runtimeEvidence(c)), 8),
		GraphEdges: supplyChainEdges(g),
		Controls:   controls,
		Actions: []string{
			"Maintain an AI-BOM or ML-BOM for model, dataset, fine-tuning, framework, tool, and MCP components.",
			"Run dependency health and provider risk reviews for agent tools, frameworks, and model services.",
			"Prefer signed artifacts, package digests, attestation, and runtime component validation for risk-bearing agent components.",
		},
		Limitations: []string{"Ariadne detects local supply-chain declarations and BOM surfaces, but does not resolve registries, validate signatures, inspect model weights, verify provider claims, or execute runtime attestation."},
	}
}

func delegationBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	controls := controlIDs(c, delegationControlIDs()...)
	controlEvidence := controlsEvidence(c, delegationControlIDs()...)
	status := model.ZeroTrustNotObserved
	finding := "No supported agent delegation or subagent surface was observed."
	if hasDelegationSurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Agent delegation surfaces exist, but Ariadne did not observe explicit delegation scope, agent-to-agent authorization, or original-intent verification evidence."
	}
	if len(controlEvidence) > 0 && hasDelegationSurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed delegation control evidence, but not enough to prove a hard delegation trust boundary."
	}
	if hasRiskyDelegation(c) && !hasHardDelegationBoundary(c) {
		status = model.ZeroTrustBreaking
		finding = "Delegated or sub-agent work can inherit privileged parent authority without observed hard delegation scope or agent-to-agent authorization controls."
	}
	if hasDelegationSurface(c) && hasHardDelegationBoundary(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed hard delegation trust-boundary evidence such as scoped delegation plus agent-to-agent authorization, or original-intent verification plus delegated credential scoping."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:delegation-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "Agent delegation boundary",
		Tier:       "enterprise",
		Status:     status,
		DesignTest: "Delegated agents should verify caller identity, original user intent, and delegated authority scope instead of inheriting the parent agent's full authority.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, delegationEvidence(c)), 8),
		GraphEdges: delegationEdges(g),
		Controls:   controls,
		Actions: []string{
			"Require explicit allowlists and authorization for agent-to-agent delegation.",
			"Downscope delegated credentials and permissions to the delegated task.",
			"Log delegation handoffs with request provenance and original user intent.",
		},
		Limitations: []string{"Ariadne detects declared delegation surfaces and controls, but does not validate live inter-agent authorization, runtime credential downscoping, or actual delegated task execution."},
	}
}

func memoryBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	evidence := memoryEvidence(c)
	controlEvidence := controlsEvidence(c, memoryControlIDs()...)
	status := model.ZeroTrustNotObserved
	finding := "No supported memory, history, paste cache, or private context surface was observed."
	edges := memoryEdges(g)
	controls := controlIDs(c, memoryControlIDs()...)
	if hasMemoryRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Private context surfaces exist; Ariadne summarizes them but did not observe isolation, retention, integrity, and provenance controls."
	}
	if hasMemoryRelevantSurface(c) && len(controls) > 0 && !hasHardMemoryBoundary(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed some memory-control evidence, but not enough to prove isolation plus retention plus integrity and provenance."
	}
	if privateContextReachable(g) && !hasHardMemoryBoundary(c) {
		status = model.ZeroTrustBreaking
		finding = "Agent authority reaches private context or history surfaces without hard memory isolation, retention, integrity, and provenance controls."
	}
	if hasMemoryCredentialRetention(c) && !hasHardMemoryBoundary(c) {
		status = model.ZeroTrustBreaking
		finding = "Credential-like material appears retained in private agent context without observed memory isolation, retention, integrity, provenance, and credential-isolation evidence."
	}
	if hasMemoryRelevantSurface(c) && hasHardMemoryBoundary(c) {
		status = model.ZeroTrustControlled
		finding = "Private context surfaces exist, and Ariadne observed hard memory controls: isolation, retention, integrity, provenance, and credential isolation when needed."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:memory-boundary",
		Principle:  "Assume breach",
		Boundary:   "Memory and context boundary",
		Tier:       "enterprise",
		Status:     status,
		DesignTest: "Persisted context should be isolated, bounded by retention, integrity-checked, provenance-tagged, and protected from credential retention across sessions.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(evidence, controlEvidence), 8),
		GraphEdges: edges,
		Controls:   controls,
		Actions: []string{
			"Keep histories, paste caches, and memory stores outside broad agent-readable roots.",
			"Define retention, isolation, integrity, and provenance controls for persisted agent context.",
			"Prevent credentials and tokens from being cached in shared or reusable agent memory.",
		},
		Limitations: []string{"Ariadne summarizes private context metadata only; it does not inspect private history contents or validate live memory quarantine and rollback behavior."},
	}
}

func identityBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	status := model.ZeroTrustNotObserved
	finding := "No supported agent runtime or authority was observed."
	credentialBoundary := boundaryEvidence(c, "boundary:credential-material")
	identityControls := controlsEvidence(c, identityControlIDs()...)
	hasStrongIdentity := hasAnyControl(c, strongIdentityControlIDs()...)
	hasScopedIssuance := hasAnyControl(c, scopedCredentialControlIDs()...)
	hasHardIdentity := hasHardIdentityBoundary(c)
	evidence := limitEvidence(firstEvidence(credentialBoundary, identityControls, runtimeEvidence(c), authorityEvidence(c), toolEvidence(c)), 8)
	if len(c.Runtimes) > 0 || len(c.Authorities) > 0 || len(c.Tools) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Agent runtime or authority exists, but Ariadne did not collect evidence for strong per-agent identity and scoped credential issuance."
	}
	if len(identityControls) > 0 && len(credentialBoundary) == 0 {
		switch {
		case hasStrongIdentity && hasScopedIssuance:
			status = model.ZeroTrustControlled
			finding = "Ariadne observed strong agent identity evidence plus scoped or ephemeral credential issuance evidence."
		case hasScopedIssuance && !hasStrongIdentity:
			status = model.ZeroTrustUnknown
			finding = "Ariadne observed scoped credential issuance evidence, but not cryptographic, hardware-bound, or per-agent identity evidence."
		case hasStrongIdentity && !hasScopedIssuance:
			status = model.ZeroTrustUnknown
			finding = "Ariadne observed strong agent identity evidence, but not short-lived, JIT, token-lifetime, or credential-helper issuance evidence."
		default:
			status = model.ZeroTrustUnknown
			finding = "Ariadne observed identity-related policy evidence, but not enough to prove strong identity plus scoped credential issuance."
		}
	}
	if hasIdentityRisk(c) && !hasHardIdentity && len(credentialBoundary) == 0 {
		status = model.ZeroTrustBreaking
		finding = "High-risk agent authority or tool surfaces exist without strong scoped agent identity; actions may be attributable only to inherited local user authority."
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
		GraphEdges: identityEdges(g),
		Controls:   controlIDs(c, identityControlIDs()...),
		Actions: []string{
			"Prefer cryptographic or per-agent identities with short-lived, JIT, or token-limited credential issuance.",
			"Do not let high-risk agent actions rely only on inherited local user authority.",
		},
		Limitations: []string{"Ariadne detects declared identity and credential controls, but does not validate identity-provider policy, token TTL, JIT authorization, ABAC rules, hardware binding, or runtime enforcement."},
	}
}

func workloadAuthorizationBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	status := model.ZeroTrustNotObserved
	finding := "No supported agent runtime, authority, or tool surface was observed."
	controls := controlIDs(c, append(workloadControlIDs(), "control:sandbox-isolation", "control:network-restricted")...)
	evidence := limitEvidence(firstEvidence(controlsEvidence(c, append(workloadControlIDs(), "control:sandbox-isolation", "control:network-restricted")...), runtimeEvidence(c), authorityEvidence(c), toolEvidence(c)), 8)
	if len(c.Runtimes) > 0 || len(c.Authorities) > 0 || len(c.Tools) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Agent runtime or authority exists, but Ariadne did not observe ABAC, named-caller, segmentation, or tool-scope authorization evidence."
	}
	if hasAnyControl(c, "control:sandbox-isolation", "control:network-restricted") && !hasStrongWorkloadAuthorization(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed sandbox or network restriction evidence, but not identity-aware workload authorization evidence."
	}
	if hasWorkloadAuthorizationRisk(c) && !hasStrongWorkloadAuthorization(c) {
		status = model.ZeroTrustBreaking
		finding = "High-risk agent authority or tool surfaces exist without identity-aware workload authorization by caller, context, segment, or tool scope."
	}
	if hasStrongWorkloadAuthorization(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed identity-aware workload authorization evidence such as ABAC, named callers, segmentation, or tool scope."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:workload-authorization-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "Workload authorization boundary",
		Tier:       "enterprise",
		Status:     status,
		DesignTest: "Agent identity should be authorized by caller, context, network segment, and tool scope before authority is granted.",
		Finding:    finding,
		Evidence:   evidence,
		GraphEdges: workloadEdges(g),
		Controls:   controls,
		Actions: []string{
			"Declare named callers, ABAC conditions, network segments, and per-tool scopes for agent workloads.",
			"Treat sandboxing as containment; require identity-aware authorization for the workload path.",
		},
		Limitations: []string{"Ariadne detects declared workload authorization controls, but does not validate identity-provider policy, ABAC evaluation, network enforcement, or runtime authorization decisions."},
	}
}

func continuousAuthorizationBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	controls := controlIDs(c, continuousAuthorizationControlIDs()...)
	controlEvidence := controlsEvidence(c, continuousAuthorizationControlIDs()...)
	riskEvidence := firstEvidence(authorityEvidence(c), toolEvidence(c), runtimeEvidence(c))
	status := model.ZeroTrustNotObserved
	finding := "No supported agent authority or continuous authorization surface was observed."
	if hasRuntimeOrAuthority(c) || len(c.Tools) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Agent runtime or authority exists, but Ariadne did not observe per-action authorization, dynamic privilege scoping, and automatic revocation evidence."
	}
	if len(controlEvidence) > 0 && !hasHardContinuousAuthorization(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed authorization evidence, but not enough to prove per-action authorization plus dynamic/JIT scoping plus automatic revocation."
	}
	if hasStandingAuthorityRisk(c) && !hasHardContinuousAuthorization(c) {
		status = model.ZeroTrustBreaking
		finding = "Standing high-risk agent authority exists without observed continuous authorization, dynamic privilege scoping, and automatic revocation evidence."
	}
	if (hasRuntimeOrAuthority(c) || len(c.Tools) > 0 || len(controlEvidence) > 0) && hasHardContinuousAuthorization(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed hard continuous authorization evidence: per-action policy checks, dynamic or JIT scoping, and automatic revocation."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:continuous-authorization-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "Continuous authorization boundary",
		Tier:       "advanced",
		Status:     status,
		DesignTest: "Agent authority should be re-authorized per action and elevated only for the task window, with access revoked when risk or task state changes.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, riskEvidence), 8),
		GraphEdges: authorizationEdges(g),
		Controls:   controls,
		Actions: []string{
			"Evaluate authorization for each agent action or tool invocation, not only at session start.",
			"Use dynamic privilege scoping, JIT elevation, or just-enough-access for high-risk authority.",
			"Automatically revoke or downscope access when the task completes, policy fails, or risk changes.",
		},
		Limitations: []string{"Ariadne detects declared authorization controls and static authority risk, but does not validate live policy decisions, IdP rules, token revocation, or runtime enforcement."},
	}
}

func approvalBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	controls := controlIDs(c, approvalControlIDs()...)
	controlEvidence := controlsEvidence(c, approvalControlIDs()...)
	riskEvidence := approvalRiskEvidence(c)
	status := model.ZeroTrustNotObserved
	finding := "No supported high-risk agent action surface was observed."
	if hasApprovalRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		finding = "High-risk agent authority or tool surfaces exist, but Ariadne did not observe approval-gate and approval-log evidence."
	}
	if len(controlEvidence) > 0 && !hasHardApprovalBoundary(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed approval-related evidence, but not both an approval gate and approval/audit logging evidence."
	}
	if hasApprovalRelevantSurface(c) && !hasApprovalGate(c) {
		status = model.ZeroTrustBreaking
		finding = "High-risk agent authority or tool surfaces exist without an observed human approval gate."
	}
	if hasApprovalRelevantSurface(c) && hasHardApprovalBoundary(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed a human approval gate plus approval or audit logging evidence for high-risk agent actions."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:approval-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "Human approval boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "High-risk autonomous actions should pause for explicit human approval and record the approval decision before execution.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, riskEvidence), 8),
		GraphEdges: approvalEdges(g),
		Controls:   controls,
		Actions: []string{
			"Require approval before local execution, external communication, delegated authority, or sensitive-data access.",
			"Log approval decisions with request, actor, tool, action, and timestamp context.",
			"Treat approval prompts without decision logs as friction until they are reconstructable.",
		},
		Limitations: []string{"Ariadne detects declared approval gates and approval-log metadata, but does not validate live prompt enforcement, UI wording, or whether humans saw accurate action descriptions."},
	}
}

func resourceExhaustionBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	controls := controlIDs(c, resourceControlIDs()...)
	controlEvidence := controlsEvidence(c, resourceControlIDs()...)
	riskEvidence := firstEvidence(toolEvidence(c), authorityEvidence(c), runtimeEvidence(c))
	status := model.ZeroTrustNotObserved
	finding := "No supported agent tool, external communication, or local execution surface was observed."
	if hasResourceRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Agent runtime, authority, or tool surfaces exist, but Ariadne did not observe rate, spend, loop, timeout, concurrency, and usage-audit controls."
	}
	if len(controlEvidence) > 0 && !hasHardResourceBoundary(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed resource-control evidence, but not enough to prove bounded execution plus a stop condition plus usage audit."
	}
	if hasRunawayResourceRisk(c) && !hasHardResourceBoundary(c) {
		status = model.ZeroTrustBreaking
		finding = "Runaway agent operation is possible through tool, execution, external communication, or delegated authority without observed resource limits, circuit breakers, and usage audit evidence."
	}
	if hasResourceRelevantSurface(c) && hasHardResourceBoundary(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed hard resource-exhaustion controls: rate or spend bounds, loop/timeout/concurrency stop conditions, and usage audit evidence."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:resource-exhaustion-boundary",
		Principle:  "Least agency",
		Boundary:   "Resource exhaustion boundary",
		Tier:       "enterprise",
		Status:     status,
		DesignTest: "Automated agent operations should have bounded rate, spend, concurrency, runtime, and loop behavior so compromise cannot create unbounded cost or denial of service.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, riskEvidence), 8),
		GraphEdges: resourceEdges(g),
		Controls:   controls,
		Actions: []string{
			"Declare per-tool/API rate limits, spend ceilings, concurrency limits, and execution timeouts.",
			"Add loop guards or circuit breakers that stop repeated tool calls and runaway plans.",
			"Log resource usage, budget events, quota alerts, and circuit-breaker decisions for investigation.",
		},
		Limitations: []string{"Ariadne detects declared resource controls and static tool/authority risk, but does not validate live quota enforcement, billing systems, token accounting, or runtime circuit-breaker behavior."},
	}
}

func observabilityBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	status := model.ZeroTrustNotObserved
	finding := "No supported agent runtime, tool, or authority was observed."
	auditControls := controlsEvidence(c, observabilityControlIDs()...)
	evidence := limitEvidence(firstEvidence(auditControls, surfaceEvidenceByCategory(c, "history-cache"), runtimeEvidence(c), toolEvidence(c)), 8)
	if hasObservabilityRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed agent surfaces, but did not verify action logging plus request or trace propagation."
	}
	if len(surfaceEvidenceByCategory(c, "history-cache")) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Local history or cache surfaces exist, but Ariadne treats them as private context, not as verified request-to-action audit trails."
	}
	if len(auditControls) > 0 && !hasHardObservabilityBoundary(c) {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed observability evidence, but not both action logging and request or trace propagation."
	}
	if hasObservabilityRisk(c) && !hasAnyControl(c, observabilityControlIDs()...) {
		status = model.ZeroTrustBreaking
		finding = "High-risk agent authority or tool surfaces exist without observed action logging or request traceability evidence."
	}
	if hasObservabilityRelevantSurface(c) && hasHardObservabilityBoundary(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed action logging and request or trace propagation evidence for request-to-action reconstruction."
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
		GraphEdges: observabilityEdges(g),
		Controls:   controlIDs(c, observabilityControlIDs()...),
		Actions: []string{
			"Collect action, tool-call, approval, credential, and network audit evidence for agent sessions.",
			"Propagate request, trace, or correlation IDs from input through tool calls and outputs.",
			"Measure whether critical agent behavior would be visible quickly enough for a human to act.",
		},
		Limitations: []string{"Ariadne samples structured audit metadata only; it does not emit transcript content, validate log completeness, replay full reasoning, or prove tamper resistance unless immutable-log evidence is collected."},
	}
}

func responseBoundary(c model.Collection, g model.Graph, exposures []model.ExposureResult) model.ZeroTrustCheck {
	controls := controlIDs(c, responseControlIDs()...)
	controlEvidence := controlsEvidence(c, responseControlIDs()...)
	status := model.ZeroTrustNotObserved
	finding := "No supported agent runtime, tool, or authority was observed."
	if hasRuntimeOrAuthority(c) || len(c.Tools) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Agent runtime or authority exists, but Ariadne did not observe automated containment, session termination, credential revocation, or quarantine evidence."
	}
	if len(controlEvidence) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed response evidence, but not enough to prove detection plus capability-removing containment with auditability."
	}
	if hasExposedPath(exposures) && !hasHardResponseBoundary(c) {
		status = model.ZeroTrustBreaking
		finding = "Supported exposure paths exist without observed automated containment controls to terminate sessions, revoke credentials, quarantine workloads, or reduce authority."
	}
	if hasHardResponseBoundary(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed response evidence that combines detection or triage with capability-removing containment and audit or escalation evidence."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:response-boundary",
		Principle:  "Assume breach",
		Boundary:   "Response and containment boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "When a compromised agent path is detected, the architecture should remove or shrink the agent's authority before damage continues at machine speed.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, runtimeEvidence(c), authorityEvidence(c), toolEvidence(c)), 8),
		GraphEdges: responseEdges(g),
		Controls:   controls,
		Actions: []string{
			"Define automated response actions for suspicious agent behavior: terminate sessions, revoke credentials, quarantine workloads, or downscope access.",
			"Require audit, trace, or escalation evidence for containment actions so humans can review high-impact decisions.",
		},
		Limitations: []string{"Ariadne detects declared response and containment controls, but does not validate SOAR execution, SIEM rules, identity-provider revocation, quarantine enforcement, or live session termination."},
	}
}

func governanceBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	controls := controlIDs(c, governanceControlIDs()...)
	controlEvidence := controlsEvidence(c, governanceControlIDs()...)
	status := model.ZeroTrustNotObserved
	finding := "No supported agent runtime, tool, or authority surface was observed."
	if hasGovernanceRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		finding = "Agent surfaces exist, but Ariadne did not observe deployment inventory, ownership, approval, risk assessment, or governance review evidence."
	}
	if len(controlEvidence) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed governance evidence, but not enough to prove the deployment is registered, owned, approved, risk-assessed, and reviewed."
	}
	if hasRiskBearingDeployment(c) && !hasHardGovernanceBoundary(c) {
		status = model.ZeroTrustBreaking
		finding = "Risk-bearing agent surfaces exist without observed governance evidence for registration, accountable owner, approval, risk assessment, and review."
	}
	if hasGovernanceRelevantSurface(c) && hasHardGovernanceBoundary(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed governance evidence for registered inventory, accountable ownership, deployment approval, risk assessment, and governance review."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:governance-boundary",
		Principle:  "Never trust, always verify",
		Boundary:   "Deployment governance boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Agent deployments should be registered, owned, approved, risk-classified, and reviewable before technical controls can be trusted to match organizational intent.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, configSurfaceEvidence(c), runtimeEvidence(c), toolEvidence(c)), 8),
		GraphEdges: governanceEdges(g),
		Controls:   controls,
		Actions: []string{
			"Register agent deployments with owner, purpose, risk tier, data classification, and approval status.",
			"Review unmanaged local agent usage as Shadow AI until ownership and approval evidence exists.",
		},
		Limitations: []string{"Ariadne detects local governance declarations, but does not validate enterprise GRC systems, CMDB records, approval workflows, or organization-wide Shadow AI discovery coverage."},
	}
}

func configIntegrityBoundary(c model.Collection, g model.Graph) model.ZeroTrustCheck {
	configEvidence := configSurfaceEvidence(c)
	controls := controlIDs(c, configIntegrityControlIDs()...)
	controlEvidence := controlsEvidence(c, configIntegrityControlIDs()...)
	status := model.ZeroTrustNotObserved
	finding := "No supported agent configuration surface was observed."
	if len(configEvidence) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Agent configuration surfaces exist, but Ariadne did not observe review, signature, managed-enforcement, or immutable deployment evidence."
	}
	if len(controlEvidence) > 0 {
		status = model.ZeroTrustUnknown
		finding = "Ariadne observed configuration integrity evidence, but not enough to prove a hard configuration integrity boundary."
	}
	if hasRiskyMutableConfig(c) && !hasHardConfigIntegrity(c) {
		status = model.ZeroTrustBreaking
		finding = "Risk-bearing agent configuration exists without observed hard integrity controls for review, signature, managed enforcement, or immutable deployment."
	}
	if hasHardConfigIntegrity(c) {
		status = model.ZeroTrustControlled
		finding = "Ariadne observed hard configuration integrity evidence such as review plus version control, signed deployment verification, managed enforcement, or immutable runtime."
	}
	return model.ZeroTrustCheck{
		ID:         "zt:config-integrity-boundary",
		Principle:  "Assume breach",
		Boundary:   "Configuration integrity boundary",
		Tier:       "foundation",
		Status:     status,
		DesignTest: "Agent configuration should be reviewable, tamper-evident, centrally enforced, or replaced immutably so attackers cannot silently widen authority.",
		Finding:    finding,
		Evidence:   limitEvidence(firstEvidence(controlEvidence, configEvidence), 8),
		GraphEdges: configIntegrityEdges(g),
		Controls:   controls,
		Actions: []string{
			"Keep agent settings, MCP definitions, and policies under reviewed version control.",
			"Use signed configuration, deployment verification, managed settings enforcement, or immutable runtime images for higher-risk agents.",
		},
		Limitations: []string{"Ariadne detects declared configuration integrity controls, but does not validate Git branch protection, signature verification, MDM enforcement, admission policy, or runtime rollback behavior."},
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

func coverage(checks []model.ZeroTrustCheck) model.ZeroTrustCoverage {
	var out model.ZeroTrustCoverage
	for _, check := range checks {
		switch check.Status {
		case model.ZeroTrustUnknown:
			out.Unknown++
			out.GapDetails = append(out.GapDetails, gapForCheck(check))
		case model.ZeroTrustNotObserved:
			out.NotObserved++
			out.GapDetails = append(out.GapDetails, gapForCheck(check))
		default:
			out.Known++
		}
	}
	out.Gaps = len(out.GapDetails)
	if out.GapDetails == nil {
		out.GapDetails = []model.ZeroTrustGap{}
	}
	return out
}

func maturity(c model.Collection) model.ZeroTrustMaturity {
	requirements := []model.ZeroTrustRequirement{
		requireCryptographicIdentity(c),
		requireShortLivedCredentials(c),
		requireLeastAgencyPermissions(c),
		requireToolIntegrity(c),
		requireSupplyChainProvenance(c),
		requireIdentityBasedIsolation(c),
		requireComprehensiveLogs(c),
		requireInputValidation(c),
		requireOutputControls(c),
		requireApprovalEscalation(c),
		requireContextRetention(c),
		requireAutomatedTriage(c),
		requireDeploymentGovernance(c),
	}
	for i := range requirements {
		requirements[i] = normalizeRequirement(requirements[i])
	}
	return model.ZeroTrustMaturity{
		TargetTier:   "foundation",
		Summary:      summarizeMaturity(requirements),
		Requirements: requirements,
	}
}

func requireCryptographicIdentity(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, strongIdentityControlIDs()...)
	evidence := firstEvidence(
		boundaryEvidence(c, "boundary:credential-material"),
		controlsEvidence(c, strongIdentityControlIDs()...),
		runtimeEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported agent runtime was observed, so Ariadne did not evaluate agent identity."
	missing := []string{"cryptographically rooted agent identity", "agent lifecycle identity evidence"}
	if hasRuntimeOrAuthority(c) {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Agent runtime or authority exists, but Ariadne did not observe cryptographic, hardware-bound, or per-agent identity evidence."
	}
	if len(controls) > 0 {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed declared cryptographic, hardware-bound, workload, or per-agent identity evidence."
		missing = nil
	}
	if hasIdentityRisk(c) && len(controls) == 0 {
		status = model.ZeroTrustBreaking
		quality = "missing_hard_barrier"
		finding = "High-risk agent authority exists without cryptographic, hardware-bound, or per-agent identity evidence."
		missing = []string{"cryptographically rooted agent identity", "per-agent or hardware-bound identity evidence"}
	}
	if hasBoundaryID(c, "boundary:credential-material") {
		status = model.ZeroTrustBreaking
		quality = "broken_static_credential"
		finding = "Inline credential material indicators were observed; this breaks the Foundation expectation for cryptographically rooted agent identity."
		missing = []string{"credential removal from config", "cryptographic workload identity evidence"}
	}
	return zeroTrustRequirement(
		"ztf:cryptographic-agent-identity",
		"foundation",
		"Never trust, always verify",
		"Cryptographically rooted agent identity",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Use workload identity, mTLS, SPIFFE, X.509, or equivalent cryptographic identity for agent instances.",
			"Remove inline credentials from agent configuration.",
		},
	)
}

func requireShortLivedCredentials(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, scopedCredentialControlIDs()...)
	evidence := firstEvidence(
		boundaryEvidence(c, "boundary:credential-material"),
		controlsEvidence(c, scopedCredentialControlIDs()...),
		runtimeEvidence(c),
		toolEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported agent runtime or tool authority was observed, so Ariadne did not evaluate credential lifetime."
	missing := []string{"short-lived OAuth/OIDC or federated credential evidence", "token lifetime policy"}
	if hasRuntimeOrAuthority(c) || len(c.Tools) > 0 {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Agent runtime, tool, or authority exists, but Ariadne did not observe short-lived credential evidence."
	}
	if hasControlID(c, "control:credential-helper") && !hasAnyControl(c, "control:short-lived-credential", "control:jit-access", "control:token-lifetime-policy") {
		status = model.ZeroTrustUnknown
		quality = "partial_declared"
		finding = "Ariadne observed a credential helper or vault pattern, but not short-lived identity-provider-issued credentials."
		missing = []string{"short-lived credential evidence", "token lifetime policy"}
	}
	if hasAnyControl(c, "control:short-lived-credential", "control:jit-access", "control:token-lifetime-policy") {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed declared short-lived, OAuth/OIDC, JIT, federated, or token-lifetime credential posture."
		missing = nil
	}
	if hasIdentityRisk(c) && !hasAnyControl(c, "control:short-lived-credential", "control:jit-access", "control:token-lifetime-policy") {
		status = model.ZeroTrustBreaking
		quality = "missing_hard_barrier"
		finding = "High-risk agent authority exists without short-lived, JIT, or token-limited credential issuance evidence."
		missing = []string{"short-lived credential evidence", "JIT or token lifetime policy"}
	}
	if hasBoundaryID(c, "boundary:credential-material") {
		status = model.ZeroTrustBreaking
		quality = "broken_static_credential"
		finding = "Inline credential material indicators were observed; static credentials do not meet Foundation credential posture."
		missing = []string{"static credential removal", "short-lived credential issuance evidence"}
	}
	return zeroTrustRequirement(
		"ztf:short-lived-credentials",
		"foundation",
		"Never trust, always verify",
		"Short-lived identity-provider-issued credentials",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Use short-lived OAuth/OIDC, federated, or JIT-issued credentials for agent tool access.",
			"Keep credential issuance auditable and revocable.",
		},
	)
}

func requireLeastAgencyPermissions(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, leastAgencyControlIDs()...)
	evidence := firstEvidence(
		controlsEvidence(c, leastAgencyControlIDs()...),
		authorityEvidence(c),
		toolEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported agent authority was observed, so Ariadne did not evaluate least-agency permission scope."
	missing := []string{"deny-by-default role or tool policy", "least-agency permission scope"}
	if len(c.Authorities) > 0 || len(c.Tools) > 0 {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Agent authority or tool surfaces exist, but Ariadne did not observe deny-by-default or least-agency scoping evidence."
	}
	if hasAuthority(c, "authority:broad-local") {
		status = model.ZeroTrustBreaking
		quality = "conflicting_broad_authority"
		finding = "Broad local authority exists; least-agency evidence is not satisfied until broad standing authority is removed or replaced with scoped permissions."
		missing = []string{"remove broad local authority", "replace bypass or full-access mode with scoped permissions"}
	}
	if !hasAuthority(c, "authority:broad-local") && hasAnyControl(c, leastAgencyControlIDs()...) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed scoped permission, deny-by-default, deny-read, network restriction, or reviewed tool-scoping controls."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:least-agency-permissions",
		"foundation",
		"Least agency",
		"Deny-by-default least-agency permissions",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Declare deny-by-default roles and tool scopes for each agent function.",
			"Remove broad local authority unless a graph-backed control restricts the reachable boundary.",
		},
	)
}

func requireToolIntegrity(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, toolIntegrityControlIDs()...)
	evidence := firstEvidence(
		controlsEvidence(c, toolIntegrityControlIDs()...),
		toolIntegrityEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported model-callable tool surface was observed, so Ariadne did not evaluate tool integrity."
	missing := []string{"approved tool allowlist", "tool package pinning or signature evidence", "tool descriptor and argument validation evidence"}
	if hasToolIntegritySurface(c) {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Model-callable tool surfaces exist, but Ariadne did not observe hard tool provenance or invocation-validation evidence."
	}
	if len(controls) > 0 && !hasHardToolIntegrity(c) {
		status = model.ZeroTrustUnknown
		quality = "partial_declared"
		finding = "Ariadne observed tool security controls, but not enough to prove allowlist plus pinning, signed verification, descriptor validation, or authenticated short-lived tool access."
		missing = []string{"hard tool provenance boundary", "tool descriptor or argument validation", "signed or pinned tool artifacts"}
	}
	if hasRiskyToolSurface(c) && !hasHardToolIntegrity(c) {
		status = model.ZeroTrustBreaking
		quality = "missing_hard_barrier"
		finding = "Risk-bearing model-callable tool surfaces exist without hard tool integrity evidence."
		missing = []string{"approved tool allowlist", "package pinning or signed artifact verification", "tool descriptor and argument validation"}
	}
	if hasToolIntegritySurface(c) && hasHardToolIntegrity(c) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed hard tool integrity evidence for model-callable tools."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:tool-integrity",
		"foundation",
		"Never trust, always verify",
		"Tool allowlisting, provenance, and invocation validation",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Allowlist approved tools and MCP servers per agent function.",
			"Pin or sign tool artifacts and validate descriptors, schemas, and arguments before execution.",
			"Use authenticated, short-lived access for sensitive tools.",
		},
	)
}

func requireSupplyChainProvenance(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, supplyChainControlIDs()...)
	evidence := firstEvidence(
		controlsEvidence(c, supplyChainControlIDs()...),
		supplyChainEvidence(c),
		toolIntegrityEvidence(c),
		runtimeEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported tool, plugin, model, or AI supply-chain surface was observed, so Ariadne did not evaluate supply-chain provenance."
	missing := []string{"AI-BOM or ML-BOM", "model provenance or provider review", "dependency health evidence", "artifact signing or runtime validation evidence"}
	if hasSupplyChainRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Agent supply-chain surfaces exist, but Ariadne did not observe AI-BOM, model provenance, dependency health, provider review, signing, or runtime validation evidence."
	}
	if len(controls) > 0 && !hasHardSupplyChainBoundary(c) {
		status = model.ZeroTrustUnknown
		quality = "partial_declared"
		finding = "Ariadne observed supply-chain evidence, but not enough to prove BOM plus dependency health plus provenance or provider review plus artifact validation."
		missing = []string{"complete AI-BOM or ML-BOM", "dependency health or reachability evidence", "model provenance, dataset lineage, or provider review", "signed artifact or runtime validation evidence"}
	}
	if hasRiskySupplyChainSurface(c) && !hasHardSupplyChainBoundary(c) {
		status = model.ZeroTrustBreaking
		quality = "missing_hard_barrier"
		finding = "Risk-bearing agent supply-chain surfaces exist without complete AI-BOM, provenance, dependency-health, provider-review, signing, or runtime-validation evidence."
		missing = []string{"AI-BOM or ML-BOM", "model or provider provenance", "dependency health or reachability analysis", "artifact signing or runtime validation"}
	}
	if hasSupplyChainRelevantSurface(c) && hasHardSupplyChainBoundary(c) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed AI-BOM, dependency health, provenance or provider review, and artifact signing or runtime validation evidence."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:supply-chain-provenance",
		"foundation",
		"Never trust, always verify",
		"AI-BOM, model provenance, dependency health, and artifact validation",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Maintain an AI-BOM or ML-BOM for model, dataset, framework, MCP, plugin, and tool components.",
			"Attach dependency health, provider review, and reachability evidence to agent component inventories.",
			"Require signed artifacts, package digests, attestations, or runtime validation before agent components extend capability.",
		},
	)
}

func requireIdentityBasedIsolation(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, append(workloadControlIDs(), "control:sandbox-isolation", "control:network-restricted")...)
	evidence := firstEvidence(
		controlsEvidence(c, append(workloadControlIDs(), "control:sandbox-isolation", "control:network-restricted")...),
		runtimeEvidence(c),
		authorityEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported agent runtime or authority was observed, so Ariadne did not evaluate workload isolation."
	missing := []string{"identity-based isolation policy", "named-caller or network segmentation evidence"}
	if hasRuntimeOrAuthority(c) {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Agent runtime or authority exists, but Ariadne did not observe identity-based workload isolation evidence."
	}
	if hasAnyControl(c, "control:sandbox-isolation", "control:network-restricted") && !hasStrongWorkloadAuthorization(c) {
		status = model.ZeroTrustUnknown
		quality = "partial_declared"
		finding = "Ariadne observed sandbox or network restriction evidence, but not identity-aware workload authorization evidence."
		missing = []string{"identity-based workload isolation evidence", "ABAC or named-caller evidence", "tool scope or network segmentation evidence"}
	}
	if hasWorkloadAuthorizationRisk(c) && !hasStrongWorkloadAuthorization(c) {
		status = model.ZeroTrustBreaking
		quality = "missing_hard_barrier"
		finding = "High-risk agent authority exists without identity-aware workload authorization evidence."
		missing = []string{"ABAC or named-caller authorization evidence", "network segmentation or per-tool scope evidence"}
	}
	if hasStrongWorkloadAuthorization(c) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed declared identity-aware workload authorization and isolation evidence."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:identity-based-isolation",
		"foundation",
		"Assume breach",
		"Identity-based workload isolation",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Constrain agent workloads with identity-based isolation, ABAC, named callers, network segmentation, and tool scopes.",
			"Use sandboxing as a containment layer, not the workload authorization boundary.",
		},
	)
}

func requireComprehensiveLogs(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, observabilityControlIDs()...)
	evidence := firstEvidence(
		controlsEvidence(c, observabilityControlIDs()...),
		surfaceEvidenceByCategory(c, "history-cache"),
		runtimeEvidence(c),
		toolEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported agent runtime or tool surface was observed, so Ariadne did not evaluate comprehensive logging."
	missing := []string{"tool-call audit log evidence", "request context and agent identity in logs", "trace or correlation IDs"}
	if len(c.Runtimes) > 0 || len(c.Tools) > 0 || len(c.Authorities) > 0 {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Agent runtime, tool, or authority exists, but Ariadne did not observe comprehensive action logging evidence."
	}
	if hasControlID(c, "control:audit-logging") && !hasControlID(c, "control:request-traceability") {
		status = model.ZeroTrustUnknown
		quality = "partial_declared"
		finding = "Ariadne observed audit logging, but not request or trace propagation evidence."
		missing = []string{"request ID, trace ID, or provenance propagation evidence"}
	}
	if hasAnyControl(c, "control:agent-action-log-evidence", "control:tool-call-audit-evidence") && !hasAnyControl(c, "control:request-traceability", "control:observed-request-traceability") {
		status = model.ZeroTrustUnknown
		quality = "partial_observed"
		finding = "Ariadne observed structured action or tool-call log metadata, but not request or trace propagation evidence."
		missing = []string{"request ID, trace ID, or provenance propagation evidence"}
	}
	if (hasControlID(c, "control:audit-logging") && hasControlID(c, "control:request-traceability")) ||
		(hasAnyControl(c, "control:agent-action-log-evidence", "control:tool-call-audit-evidence") && hasAnyControl(c, "control:request-traceability", "control:observed-request-traceability")) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed action logging and request traceability evidence for agent activity reconstruction."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:comprehensive-agent-logs",
		"foundation",
		"Assume breach",
		"Comprehensive logs of agent actions with context",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Log tool invocations, data access, approvals, external communication, agent identity, and request context.",
			"Propagate request or trace IDs through agent actions.",
		},
	)
}

func requireInputValidation(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, inputControlIDs()...)
	evidence := firstEvidence(
		controlsEvidence(c, inputControlIDs()...),
		trustInputEvidence(c, true),
		trustInputEvidence(c, false),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported untrusted instruction surface was observed, so Ariadne did not evaluate input validation."
	missing := []string{"schema or length validation", "known prompt-injection payload filtering", "untrusted input delimiting policy"}
	if len(c.TrustInputs) > 0 {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Instruction inputs exist, but Ariadne did not observe input validation or untrusted-content boundary evidence."
	}
	if len(trustInputEvidence(c, true)) > 0 && len(controls) == 0 {
		status = model.ZeroTrustBreaking
		quality = "missing_hard_barrier"
		finding = "Risky untrusted instruction input exists without observed input validation or prompt-injection filtering evidence."
	}
	if len(controls) > 0 && !hasHardInputControl(c) {
		status = model.ZeroTrustUnknown
		quality = "partial_declared"
		finding = "Ariadne observed input validation, provenance, delimiting, or filtering evidence, but not input-isolation or trusted-source controls that break the influence path."
		missing = []string{"input isolation policy", "trusted source gate for instruction inputs"}
	}
	if hasHardInputControl(c) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed input-isolation or trusted-source controls for untrusted instruction inputs."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:input-validation",
		"foundation",
		"Never trust, always verify",
		"Input validation for untrusted agent context",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Isolate untrusted instructions from authority-bearing runtime behavior.",
			"Use trusted-source gates, provenance, validation, and explicit untrusted-content delimiting for repo, web, email, and document inputs.",
		},
	)
}

func requireOutputControls(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, outputControlIDs()...)
	evidence := firstEvidence(
		controlsEvidence(c, outputControlIDs()...),
		boundaryEvidence(c, "boundary:secret-like-file", "boundary:developer-secret-boundary", "boundary:agent-private-context", "boundary:credential-material"),
		authorityEvidenceByID(c, "authority:file-read", "authority:broad-local"),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported sensitive-output risk surface was observed, so Ariadne did not evaluate output controls."
	missing := []string{"sensitive-output filter", "block or redaction policy", "output filtering event logs"}
	if hasOutputRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Agent output or sensitive boundary evidence exists, but Ariadne did not observe sensitive-output filtering, redaction, and logging controls."
	}
	if len(controls) > 0 && !hasHardOutputBoundary(c) {
		status = model.ZeroTrustUnknown
		quality = "partial_declared"
		finding = "Ariadne observed output-control evidence, but not filtering plus block/redaction plus logging."
		missing = []string{"sensitive-output filter", "block or redaction policy", "output-control log evidence"}
	}
	if hasOutputLeakRisk(c, nil) && !hasOutputBlockingControl(c) {
		status = model.ZeroTrustBreaking
		quality = "missing_hard_barrier"
		finding = "Sensitive agent output can be produced from reachable private data without observed filtering, redaction, and output-control logging evidence."
		missing = []string{"sensitive-output filter", "block or redaction policy", "output-control log evidence"}
	}
	if hasOutputRelevantSurface(c) && hasHardOutputBoundary(c) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed output filtering, block or redaction, and logging evidence."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:output-controls",
		"foundation",
		"Assume breach",
		"Output filtering, redaction, and logging for sensitive agent output",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Filter agent outputs for credentials, PII, and sensitive business data.",
			"Block or redact detected sensitive output before it reaches users or external tools.",
			"Log output filtering decisions for incident reconstruction and compliance review.",
		},
	)
}

func requireApprovalEscalation(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, approvalControlIDs()...)
	evidence := firstEvidence(
		controlsEvidence(c, approvalControlIDs()...),
		approvalRiskEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported high-risk tool or authority surface was observed, so Ariadne did not evaluate approval escalation."
	missing := []string{"approval trigger policy for high-risk actions", "approval decision log evidence"}
	if hasApprovalRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "High-risk authority or tool surfaces exist, but Ariadne did not observe approval escalation evidence."
	}
	if hasApprovalGate(c) && !hasApprovalAudit(c) {
		status = model.ZeroTrustUnknown
		quality = "friction_only"
		finding = "Ariadne observed approval prompts, but not approval decision logging; this is treated as friction until forensic evidence exists."
		missing = []string{"approval decision log evidence", "tool-call audit trail"}
	}
	if hasHardApprovalBoundary(c) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed declared approval escalation with audit logging evidence."
		missing = nil
	}
	if hasApprovalRelevantSurface(c) && !hasApprovalGate(c) {
		status = model.ZeroTrustBreaking
		quality = "missing_hard_barrier"
		finding = "High-risk authority or tool surfaces exist without observed approval escalation or approval logging evidence."
	}
	return zeroTrustRequirement(
		"ztf:approval-escalation",
		"foundation",
		"Least agency",
		"Approval escalation for high-risk actions",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Require approval before high-risk tool use, sensitive data access, external communication, or local execution.",
			"Log approval decisions with enough context for incident reconstruction.",
		},
	)
}

func requireContextRetention(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, memoryControlIDs()...)
	evidence := firstEvidence(
		controlsEvidence(c, memoryControlIDs()...),
		memoryEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported memory or private context surface was observed, so Ariadne did not evaluate retention."
	missing := []string{"context retention policy", "memory isolation or cleanup evidence"}
	if len(memoryEvidence(c)) > 0 {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Private context or memory surfaces exist, but Ariadne did not observe retention policy evidence."
	}
	if len(controls) > 0 {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed retention, isolation, integrity, or provenance controls for persisted context."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:context-retention",
		"foundation",
		"Assume breach",
		"Context retention policy for persisted agent memory",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Define retention windows for transcripts, memory, paste caches, and private context.",
			"Keep high-risk untrusted context short-lived and recoverable.",
		},
	)
}

func requireAutomatedTriage(c model.Collection) model.ZeroTrustRequirement {
	responseIDs := append(responseControlIDs(), "control:audit-logging", "control:request-traceability", "control:telemetry-export", "control:immutable-audit-log")
	controls := controlIDs(c, responseIDs...)
	evidence := firstEvidence(
		controlsEvidence(c, responseIDs...),
		runtimeEvidence(c),
		toolEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported agent runtime or tool surface was observed, so Ariadne did not evaluate automated first-pass triage and containment."
	missing := []string{"automated first-pass investigation evidence", "containment action evidence", "response audit or escalation evidence"}
	if len(c.Runtimes) > 0 || len(c.Tools) > 0 || len(c.Authorities) > 0 {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Agent runtime, tool, or authority exists, but Ariadne did not observe automated first-pass triage and containment evidence."
	}
	if len(controls) > 0 && !hasHardResponseBoundary(c) {
		status = model.ZeroTrustUnknown
		quality = "partial_declared"
		finding = "Ariadne observed response evidence, but not detection plus capability-removing containment plus audit or escalation evidence."
		missing = []string{"session termination, credential revocation, quarantine, or dynamic access reduction evidence", "response audit, trace, telemetry, or escalation evidence"}
	}
	if hasHardResponseBoundary(c) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed declared automated first-pass investigation, containment, and audit or escalation controls."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:automated-first-pass-triage",
		"foundation",
		"Assume breach",
		"Automated first-pass investigation and containment for agent alerts",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Route agent alerts through automated first-pass investigation before human review.",
			"Define containment actions that terminate sessions, revoke credentials, quarantine workloads, or reduce authority.",
			"Measure detection speed, response speed, and alert coverage for critical agent behavior.",
		},
	)
}

func requireDeploymentGovernance(c model.Collection) model.ZeroTrustRequirement {
	controls := controlIDs(c, governanceControlIDs()...)
	evidence := firstEvidence(
		controlsEvidence(c, governanceControlIDs()...),
		configSurfaceEvidence(c),
		runtimeEvidence(c),
		toolEvidence(c),
	)
	status := model.ZeroTrustNotObserved
	quality := "not_applicable"
	finding := "No supported agent deployment surface was observed, so Ariadne did not evaluate deployment governance."
	missing := []string{"agent inventory evidence", "accountable owner", "deployment approval and risk assessment"}
	if hasGovernanceRelevantSurface(c) {
		status = model.ZeroTrustUnknown
		quality = "evidence_gap"
		finding = "Agent deployment surfaces exist, but Ariadne did not observe inventory, owner, approval, risk assessment, and governance review evidence."
	}
	if len(controls) > 0 && !hasHardGovernanceBoundary(c) {
		status = model.ZeroTrustUnknown
		quality = "partial_declared"
		finding = "Ariadne observed governance evidence, but not enough to prove registered inventory, accountable owner, deployment approval, risk assessment, and review."
		missing = []string{"deployment approval evidence", "risk tier or data classification evidence", "governance review evidence"}
	}
	if hasRiskBearingDeployment(c) && !hasHardGovernanceBoundary(c) {
		status = model.ZeroTrustBreaking
		quality = "missing_hard_barrier"
		finding = "Risk-bearing agent surfaces exist without complete deployment governance evidence."
		missing = []string{"agent inventory evidence", "accountable owner", "deployment approval", "risk assessment", "governance review"}
	}
	if hasGovernanceRelevantSurface(c) && hasHardGovernanceBoundary(c) {
		status = model.ZeroTrustControlled
		quality = "hard_barrier"
		finding = "Ariadne observed registered inventory, accountable ownership, deployment approval, risk assessment, and governance review evidence."
		missing = nil
	}
	return zeroTrustRequirement(
		"ztf:deployment-governance",
		"foundation",
		"Never trust, always verify",
		"Registered, owned, approved, risk-assessed, and reviewed agent deployments",
		status,
		quality,
		finding,
		evidence,
		controls,
		missing,
		[]string{
			"Register agent deployments with owner, purpose, risk tier, and data classification.",
			"Require approval and review cadence for new or changed agent deployments.",
			"Treat unregistered risk-bearing local agents as Shadow AI until governance evidence exists.",
		},
	)
}

func zeroTrustRequirement(id, tier, principle, capability string, status model.ZeroTrustStatus, quality, finding string, evidence []model.ZeroTrustEvidence, controls, missing, actions []string) model.ZeroTrustRequirement {
	return model.ZeroTrustRequirement{
		ID:              id,
		Tier:            tier,
		Principle:       principle,
		Capability:      capability,
		Status:          status,
		ControlQuality:  quality,
		Finding:         finding,
		Evidence:        limitEvidence(evidence, 8),
		Controls:        uniqueStrings(controls),
		MissingEvidence: uniqueStrings(missing),
		Actions:         uniqueStrings(actions),
	}
}

func normalizeRequirement(req model.ZeroTrustRequirement) model.ZeroTrustRequirement {
	if req.Evidence == nil {
		req.Evidence = []model.ZeroTrustEvidence{}
	}
	if req.Controls == nil {
		req.Controls = []string{}
	}
	if req.MissingEvidence == nil {
		req.MissingEvidence = []string{}
	}
	if req.Actions == nil {
		req.Actions = []string{}
	}
	return req
}

func summarizeMaturity(requirements []model.ZeroTrustRequirement) model.ZeroTrustMaturitySummary {
	var summary model.ZeroTrustMaturitySummary
	summary.Total = len(requirements)
	for _, req := range requirements {
		switch req.Status {
		case model.ZeroTrustControlled:
			summary.Met++
		case model.ZeroTrustBreaking:
			summary.Breaking++
			summary.Gaps++
		case model.ZeroTrustUnknown:
			summary.Unknown++
			summary.Gaps++
		case model.ZeroTrustNotObserved:
			summary.NotObserved++
		default:
			summary.Gaps++
		}
		switch req.ControlQuality {
		case "hard_barrier":
			summary.HardBarriers++
		case "friction_only":
			summary.FrictionOnly++
		}
	}
	return summary
}

func gapForCheck(check model.ZeroTrustCheck) model.ZeroTrustGap {
	gap := model.ZeroTrustGap{
		CheckID:  check.ID,
		Boundary: check.Boundary,
		Status:   check.Status,
	}
	switch check.ID {
	case "zt:influence-boundary":
		gap.MissingEvidence = []string{
			"runtime input-isolation policy",
			"instruction provenance or trust policy",
			"approval evidence for untrusted-instruction execution",
		}
		gap.WhyItMatters = "Without input-isolation evidence, Ariadne cannot prove whether untrusted instructions are separated from authority-bearing runtime behavior."
		gap.NextCollector = "Collect runtime permission policy, trusted-source policy, and approval/tool-call logs."
	case "zt:authority-boundary":
		gap.MissingEvidence = []string{
			"least-agency tool scope",
			"sandbox enforcement evidence",
			"per-tool filesystem/network scope",
		}
		gap.WhyItMatters = "Without authority-scope evidence, Ariadne cannot prove whether broad agent permissions are necessary or constrained."
		gap.NextCollector = "Collect sandbox profile, filesystem root, network scope, and per-tool permission metadata."
	case "zt:sensitive-boundary":
		gap.MissingEvidence = []string{
			"complete sensitive-boundary inventory",
			"deny-read coverage for secrets and private context",
			"control evidence for external destinations",
		}
		gap.WhyItMatters = "Without boundary and control coverage, Ariadne cannot prove whether sensitive data paths are fully broken."
		gap.NextCollector = "Collect secret-boundary indicators, deny-read rules, private-context locations, and network policy."
	case "zt:egress-boundary":
		gap.MissingEvidence = []string{
			"approved external destination policy",
			"webhook destination allowlist",
			"per-tool network scope evidence",
		}
		gap.WhyItMatters = "Without egress boundary evidence, Ariadne cannot prove that private data cannot leave through arbitrary external communication paths."
		gap.NextCollector = "Collect egress policy, webhook allowlists, outbound destination rules, per-tool network scope, and egress audit metadata."
	case "zt:output-boundary":
		gap.MissingEvidence = []string{
			"sensitive-output filtering policy",
			"block or redaction policy for credentials, PII, and sensitive business data",
			"output filtering event logs",
		}
		gap.WhyItMatters = "Without output-control evidence, a compromised or manipulated agent can expose sensitive data in its response even when network egress is separately constrained."
		gap.NextCollector = "Collect output policy, DLP or sensitive-output filter declarations, redaction/blocking rules, semantic output review settings, human-review triggers, and output filtering event logs."
	case "zt:tool-boundary":
		gap.MissingEvidence = []string{
			"tool allowlist",
			"package pinning or digest evidence",
			"tool provenance and launch review evidence",
		}
		gap.WhyItMatters = "Without tool provenance and scoping evidence, mutable or remote tool surfaces remain uncertain."
		gap.NextCollector = "Collect MCP allowlists, lockfiles, package digests, plugin manifests, and tool review policy."
	case "zt:tool-integrity-boundary":
		gap.MissingEvidence = []string{
			"approved tool or MCP server allowlist",
			"package pinning, digest, signature, or deployment verification evidence",
			"tool descriptor integrity, authentication, and argument-validation evidence",
		}
		gap.WhyItMatters = "Without tool integrity evidence, a compromised or mutable model-callable tool can change what the agent believes it is calling or what capability it receives."
		gap.NextCollector = "Collect tool policy, MCP allowlists, descriptor/signature metadata, package digests, tool authentication policy, and PreToolUse or schema validation controls."
	case "zt:supply-chain-boundary":
		gap.MissingEvidence = []string{
			"AI-BOM or ML-BOM evidence",
			"model provenance, training-data lineage, or provider risk review evidence",
			"dependency health, signed artifact, runtime validation, or reachability-analysis evidence",
		}
		gap.WhyItMatters = "Without supply-chain evidence, Ariadne cannot prove that agent tools, frameworks, model components, or providers are known and tamper-resistant enough for Zero Trust architecture."
		gap.NextCollector = "Collect supply-chain policy, AI-BOM or CycloneDX ML-BOM, model provenance, dataset lineage, OpenSSF Scorecard or dependency-health results, provider assessments, signatures, attestations, and runtime validation evidence."
	case "zt:delegation-boundary":
		gap.MissingEvidence = []string{
			"delegation scope or delegated permission policy",
			"agent-to-agent authorization or delegate allowlist",
			"original-user-intent verification and delegated credential scoping evidence",
		}
		gap.WhyItMatters = "Without explicit delegation boundaries, a lower-trust or compromised agent can become a confused deputy by asking a more privileged agent to act with inherited authority."
		gap.NextCollector = "Collect delegation policy, subagent definitions, delegated credential scope, original-intent provenance, agent-to-agent authorization, and delegation audit evidence."
	case "zt:memory-boundary":
		gap.MissingEvidence = []string{
			"memory isolation policy",
			"context retention policy",
			"context integrity and provenance metadata",
			"credential exclusion or credential-isolation evidence for persisted context",
		}
		gap.WhyItMatters = "Without memory isolation and provenance evidence, poisoned or credential-bearing context can persist across sessions and become a cross-session authority path."
		gap.NextCollector = "Collect memory store locations, retention settings, transcript metadata, credential-retention indicators, context integrity/provenance controls, and memory isolation policy."
	case "zt:identity-boundary":
		gap.MissingEvidence = []string{
			"cryptographic, hardware-bound, or per-agent identity evidence",
			"short-lived, JIT, or token-lifetime credential evidence",
			"credential helper or vault issuance evidence",
		}
		gap.WhyItMatters = "Without identity evidence, Ariadne cannot prove that agent actions are attributable to scoped, expiring credentials."
		gap.NextCollector = "Collect identity policy, credential-helper config, OAuth/OIDC metadata, token lifetime policy, JIT policy, hardware-bound credential evidence, and per-agent identity scope evidence."
	case "zt:workload-authorization-boundary":
		gap.MissingEvidence = []string{
			"ABAC or context-condition policy",
			"named-caller or principal allowlist",
			"network segmentation or per-tool scope evidence",
		}
		gap.WhyItMatters = "Without workload authorization evidence, Ariadne cannot prove that an authenticated agent is allowed only for the intended callers, context, network segment, and tool scope."
		gap.NextCollector = "Collect workload policy, ABAC conditions, named-caller allowlists, network segmentation, and per-tool permission scope evidence."
	case "zt:continuous-authorization-boundary":
		gap.MissingEvidence = []string{
			"per-action or per-tool authorization policy",
			"dynamic privilege scoping, JIT elevation, or no-standing-access evidence",
			"automatic access revocation or reauthorization on risk change",
		}
		gap.WhyItMatters = "Without continuous authorization evidence, a compromised agent can keep using valid standing authority after task context, risk, or policy state changes."
		gap.NextCollector = "Collect authorization policy, real-time policy evaluation evidence, JIT/JEA elevation settings, no-standing-access declarations, revocation hooks, and policy decision logs."
	case "zt:approval-boundary":
		gap.MissingEvidence = []string{
			"approval gate for high-risk local execution, external communication, delegation, or sensitive-data access",
			"approval decision log evidence",
			"request, actor, tool, action, and timestamp context for approvals",
		}
		gap.WhyItMatters = "Without approval-gate evidence, a manipulated or compromised agent can execute high-risk actions at machine speed before a human can make an informed decision."
		gap.NextCollector = "Collect runtime approval policy, PreToolUse or ask settings, approval decision logs, tool-call logs, request IDs, and trace IDs for high-risk agent actions."
	case "zt:resource-exhaustion-boundary":
		gap.MissingEvidence = []string{
			"per-tool or API rate-limit policy",
			"spend, quota, concurrency, timeout, loop-guard, or circuit-breaker policy",
			"resource usage, budget, quota, or circuit-breaker audit logs",
		}
		gap.WhyItMatters = "Without resource-bound evidence, a manipulated or compromised agent can loop tool calls, exhaust APIs, create billing spikes, or deny service while using legitimate automation paths."
		gap.NextCollector = "Collect resource policy, tool/API rate limits, spend or token budgets, loop guards, tool timeouts, concurrency limits, circuit-breaker settings, and usage or budget event logs."
	case "zt:observability-boundary":
		gap.MissingEvidence = []string{
			"tool-call audit log evidence",
			"approval log evidence",
			"telemetry export or SIEM evidence",
		}
		gap.WhyItMatters = "Without audit evidence, operators may not be able to reconstruct what the agent did or why quickly enough to respond."
		gap.NextCollector = "Collect transcript metadata, tool-call logs, approval logs, OpenTelemetry config, and SIEM export evidence."
	case "zt:response-boundary":
		gap.MissingEvidence = []string{
			"automated triage or behavioral monitoring evidence",
			"session termination, credential revocation, quarantine, or dynamic access reduction evidence",
			"audit, trace, telemetry, or escalation evidence for response actions",
		}
		gap.WhyItMatters = "Without containment evidence, a compromised agent can keep operating with valid authority while humans investigate."
		gap.NextCollector = "Collect response policy, SOAR workflow metadata, session termination controls, credential revocation policy, quarantine actions, dynamic access reduction policy, and response audit evidence."
	case "zt:governance-boundary":
		gap.MissingEvidence = []string{
			"agent inventory or registry evidence",
			"accountable owner or responsible team",
			"deployment approval, risk assessment, data classification, and governance review evidence",
		}
		gap.WhyItMatters = "Without governance evidence, Ariadne cannot tell whether observed agent authority is an approved deployment or unmanaged Shadow AI."
		gap.NextCollector = "Collect governance policy, agent inventory, owner metadata, deployment approval, risk tier, data classification, review cadence, and Shadow AI discovery evidence."
	case "zt:config-integrity-boundary":
		gap.MissingEvidence = []string{
			"reviewed version-controlled agent configuration",
			"signed configuration with deployment verification",
			"managed settings enforcement or immutable runtime evidence",
		}
		gap.WhyItMatters = "Without configuration integrity evidence, an attacker or local override can silently widen agent authority or disable controls."
		gap.NextCollector = "Collect integrity policy, managed settings enforcement, signed config metadata, deployment verification, branch protection, and rollback evidence."
	case "zt:control-strength":
		gap.MissingEvidence = []string{
			"control edge that removes the path",
			"runtime enforcement evidence",
			"policy proof for the relevant authority or boundary",
		}
		gap.WhyItMatters = "Without a break-path control, Ariadne cannot prove that the architecture removes the capability rather than adding friction."
		gap.NextCollector = "Collect deny, allowlist, sandbox, network, MCP review, and enforcement policy evidence."
	default:
		gap.MissingEvidence = []string{"deterministic evidence for this architecture boundary"}
		gap.WhyItMatters = "Ariadne needs more evidence to classify this boundary."
		gap.NextCollector = "Add a collector for the missing boundary evidence."
	}
	return gap
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

func hasControlID(c model.Collection, id string) bool {
	for _, control := range c.Controls {
		if control.ID == id {
			return true
		}
	}
	return false
}

func hasAnyControl(c model.Collection, ids ...string) bool {
	for _, id := range ids {
		if hasControlID(c, id) {
			return true
		}
	}
	return false
}

func observabilityControlIDs() []string {
	return []string{
		"control:audit-logging",
		"control:request-traceability",
		"control:observed-request-traceability",
		"control:agent-action-log-evidence",
		"control:tool-call-audit-evidence",
		"control:approval-log-evidence",
		"control:telemetry-export",
		"control:immutable-audit-log",
	}
}

func hasHardObservabilityBoundary(c model.Collection) bool {
	return hasObservabilityActionLog(c) && hasObservabilityTrace(c)
}

func hasObservabilityActionLog(c model.Collection) bool {
	return hasAnyControl(c,
		"control:audit-logging",
		"control:agent-action-log-evidence",
		"control:tool-call-audit-evidence",
		"control:approval-log-evidence",
	)
}

func hasObservabilityTrace(c model.Collection) bool {
	return hasAnyControl(c,
		"control:request-traceability",
		"control:observed-request-traceability",
	)
}

func hasObservabilityRelevantSurface(c model.Collection) bool {
	return len(c.Runtimes) > 0 ||
		len(c.Tools) > 0 ||
		len(c.Authorities) > 0 ||
		len(surfaceEvidenceByCategory(c, "history-cache")) > 0 ||
		hasAnyControl(c, observabilityControlIDs()...)
}

func hasObservabilityRisk(c model.Collection) bool {
	return hasApprovalRelevantSurface(c) ||
		hasStandingAuthorityRisk(c) ||
		hasRunawayResourceRisk(c)
}

func responseControlIDs() []string {
	return []string{
		"control:automated-triage",
		"control:behavioral-monitoring",
		"control:session-termination",
		"control:credential-revocation",
		"control:containment-quarantine",
		"control:dynamic-access-reduction",
		"control:response-escalation",
	}
}

func governanceControlIDs() []string {
	return []string{
		"control:agent-inventory",
		"control:deployment-owner",
		"control:deployment-approval",
		"control:risk-assessment",
		"control:governance-audit",
		"control:shadow-ai-discovery",
	}
}

func hardResponseContainmentControlIDs() []string {
	return []string{
		"control:session-termination",
		"control:credential-revocation",
		"control:containment-quarantine",
		"control:dynamic-access-reduction",
	}
}

func configIntegrityControlIDs() []string {
	return []string{
		"control:config-version-control",
		"control:config-review-required",
		"control:signed-config",
		"control:config-deployment-verification",
		"control:managed-settings-enforced",
		"control:managed-runtime-settings",
		"control:immutable-agent-runtime",
		"control:config-rollback-procedure",
		"control:automated-config-rollback",
	}
}

func toolIntegrityControlIDs() []string {
	return []string{
		"control:tool-allowlist",
		"control:mcp-reviewed-pinned",
		"control:tool-descriptor-integrity",
		"control:tool-argument-validation",
		"control:tool-auth-required",
		"control:signed-tool-artifacts",
		"control:tool-deployment-verification",
		"control:tool-sandbox-execution",
		"control:tool-circuit-breaker",
	}
}

func supplyChainControlIDs() []string {
	return []string{
		"control:ai-bom",
		"control:model-provenance",
		"control:training-data-lineage",
		"control:dependency-health-scan",
		"control:provider-risk-review",
		"control:signed-ai-artifacts",
		"control:runtime-component-validation",
		"control:dependency-reachability-analysis",
	}
}

func delegationControlIDs() []string {
	return []string{
		"control:delegation-scope",
		"control:delegation-allowlist",
		"control:agent-to-agent-authorization",
		"control:origin-intent-verification",
		"control:delegated-credential-scope",
		"control:subagent-context-isolation",
		"control:delegation-audit",
	}
}

func hasHardDelegationBoundary(c model.Collection) bool {
	scopedAuthorized := hasAnyControl(c, "control:delegation-scope") &&
		hasAnyControl(c, "control:agent-to-agent-authorization", "control:delegation-allowlist")
	intentDownscoped := hasAnyControl(c, "control:origin-intent-verification") &&
		hasAnyControl(c, "control:delegated-credential-scope")
	return scopedAuthorized || intentDownscoped
}

func hasDelegationSurface(c model.Collection) bool {
	return hasToolID(c, "tool:agent-delegation") ||
		hasAuthority(c, "authority:delegated-agent-authority") ||
		hasBoundaryID(c, "boundary:agent-delegation-boundary")
}

func hasRiskyDelegation(c model.Collection) bool {
	if !hasDelegationSurface(c) {
		return false
	}
	return hasAuthority(c, "authority:broad-local") ||
		hasAuthority(c, "authority:file-read") ||
		hasAuthority(c, "authority:local-code-execution") ||
		hasAuthority(c, "authority:external-communication") ||
		hasToolID(c, "tool:mcp-package-launch") ||
		hasToolID(c, "tool:agent-command-shell")
}

func hasHardToolIntegrity(c model.Collection) bool {
	reviewedPinnedAllowlist := hasAnyControl(c, "control:tool-allowlist") && hasAnyControl(c, "control:mcp-reviewed-pinned")
	signedVerified := hasAnyControl(c, "control:signed-tool-artifacts") && hasAnyControl(c, "control:tool-deployment-verification")
	descriptorValidated := hasAnyControl(c, "control:tool-descriptor-integrity") && hasAnyControl(c, "control:tool-argument-validation")
	authenticatedScoped := hasAnyControl(c, "control:tool-auth-required") && hasAnyControl(c, "control:short-lived-credential", "control:jit-access", "control:token-lifetime-policy")
	return reviewedPinnedAllowlist || signedVerified || descriptorValidated || authenticatedScoped
}

func hasToolIntegritySurface(c model.Collection) bool {
	for _, tool := range c.Tools {
		if tool.ID != "tool:agent-delegation" {
			return true
		}
	}
	return false
}

func hasRiskyToolSurface(c model.Collection) bool {
	for _, tool := range c.Tools {
		if tool.ID == "tool:agent-delegation" {
			continue
		}
		if tool.Risky || tool.ID == "tool:agent-command-shell" {
			return true
		}
	}
	return false
}

func hasHardSupplyChainBoundary(c model.Collection) bool {
	bom := hasAnyControl(c, "control:ai-bom")
	dependencyHealth := hasAnyControl(c, "control:dependency-health-scan", "control:dependency-reachability-analysis")
	provenanceOrProvider := hasAnyControl(c, "control:model-provenance", "control:training-data-lineage", "control:provider-risk-review")
	validation := hasAnyControl(c, "control:signed-ai-artifacts", "control:runtime-component-validation", "control:signed-tool-artifacts", "control:tool-deployment-verification")
	return bom && dependencyHealth && provenanceOrProvider && validation
}

func hasSupplyChainRelevantSurface(c model.Collection) bool {
	return hasToolIntegritySurface(c) ||
		len(surfaceEvidenceByCategory(c, "supply-chain-bom")) > 0 ||
		hasToolID(c, "tool:agent-plugin-surface") ||
		hasToolID(c, "tool:agent-command-shell")
}

func hasRiskySupplyChainSurface(c model.Collection) bool {
	return hasRiskyToolSurface(c) ||
		hasToolID(c, "tool:agent-plugin-surface") ||
		hasToolID(c, "tool:agent-command-shell") ||
		hasToolID(c, "tool:mcp-package-launch") ||
		hasAuthority(c, "authority:local-code-execution")
}

func hasHardOutputBoundary(c model.Collection) bool {
	return hasOutputBlockingControl(c) && hasOutputAuditControl(c)
}

func hasOutputBlockingControl(c model.Collection) bool {
	filter := hasAnyControl(c, "control:output-sensitive-data-filter", "control:semantic-output-analysis", "control:egress-content-filter")
	blockOrReview := hasAnyControl(c, "control:output-redaction", "control:high-risk-output-review")
	return filter && blockOrReview
}

func hasOutputAuditControl(c model.Collection) bool {
	return hasAnyControl(c, "control:output-filter-logging", "control:audit-logging", "control:request-traceability", "control:telemetry-export")
}

func hasOutputRelevantSurface(c model.Collection) bool {
	return len(c.Runtimes) > 0 ||
		len(c.TrustInputs) > 0 ||
		hasAnyControl(c, outputControlIDs()...) ||
		hasAnyBoundary(c, "boundary:secret-like-file", "boundary:developer-secret-boundary", "boundary:agent-private-context", "boundary:credential-material")
}

func hasOutputLeakRisk(c model.Collection, exposures []model.ExposureResult) bool {
	if hasBoundaryID(c, "boundary:credential-material") {
		return true
	}
	if statusForExposures(exposures, "prompt-injection-to-secret-canary", "data-egress-chain") == model.ZeroTrustBreaking {
		return true
	}
	privateAuthority := hasAuthority(c, "authority:file-read") || hasAuthority(c, "authority:broad-local")
	privateBoundary := hasAnyBoundary(c, "boundary:secret-like-file", "boundary:developer-secret-boundary", "boundary:agent-private-context")
	return privateAuthority && privateBoundary
}

func hasHardConfigIntegrity(c model.Collection) bool {
	reviewedVersionControl := hasAnyControl(c, "control:config-version-control") && hasAnyControl(c, "control:config-review-required")
	signedVerified := hasAnyControl(c, "control:signed-config") && hasAnyControl(c, "control:config-deployment-verification")
	return reviewedVersionControl ||
		signedVerified ||
		hasAnyControl(c, "control:managed-settings-enforced", "control:immutable-agent-runtime")
}

func hasHardResponseBoundary(c model.Collection) bool {
	detection := hasAnyControl(c, "control:automated-triage", "control:behavioral-monitoring")
	containment := hasAnyControl(c, hardResponseContainmentControlIDs()...)
	auditable := hasAnyControl(c, "control:audit-logging", "control:request-traceability", "control:telemetry-export", "control:immutable-audit-log", "control:response-escalation")
	return detection && containment && auditable
}

func hasHardGovernanceBoundary(c model.Collection) bool {
	return hasAnyControl(c, "control:agent-inventory") &&
		hasAnyControl(c, "control:deployment-owner") &&
		hasAnyControl(c, "control:deployment-approval") &&
		hasAnyControl(c, "control:risk-assessment") &&
		hasAnyControl(c, "control:governance-audit")
}

func hasGovernanceRelevantSurface(c model.Collection) bool {
	return len(c.Runtimes) > 0 ||
		len(c.Tools) > 0 ||
		len(c.Authorities) > 0 ||
		len(configSurfaceEvidence(c)) > 0
}

func hasRiskBearingDeployment(c model.Collection) bool {
	return hasAuthority(c, "authority:broad-local") ||
		hasAuthority(c, "authority:local-code-execution") ||
		hasAuthority(c, "authority:external-communication") ||
		hasAuthority(c, "authority:delegated-agent-authority") ||
		hasToolID(c, "tool:mcp-package-launch") ||
		hasToolID(c, "tool:agent-plugin-surface") ||
		hasToolID(c, "tool:agent-command-shell") ||
		hasToolID(c, "tool:agent-delegation")
}

func hasExposedPath(exposures []model.ExposureResult) bool {
	for _, exposure := range exposures {
		if exposure.Status == model.StatusExposed {
			return true
		}
	}
	return false
}

func hasRiskyMutableConfig(c model.Collection) bool {
	return hasAuthority(c, "authority:broad-local") ||
		hasAuthority(c, "authority:local-code-execution") ||
		hasAuthority(c, "authority:external-communication") ||
		hasToolID(c, "tool:mcp-package-launch") ||
		hasToolID(c, "tool:agent-plugin-surface") ||
		hasToolID(c, "tool:agent-command-shell")
}

func identityControlIDs() []string {
	return []string{
		"control:cryptographic-identity",
		"control:credential-isolation",
		"control:hardware-bound-credential",
		"control:credential-helper",
		"control:short-lived-credential",
		"control:jit-access",
		"control:token-lifetime-policy",
		"control:identity-lifecycle",
	}
}

func hasHardIdentityBoundary(c model.Collection) bool {
	return hasAnyControl(c, strongIdentityControlIDs()...) && hasAnyControl(c, scopedCredentialControlIDs()...)
}

func hasIdentityRisk(c model.Collection) bool {
	return hasApprovalRelevantSurface(c) || hasRiskyToolSurface(c) || hasStandingAuthorityRisk(c)
}

func strongIdentityControlIDs() []string {
	return []string{
		"control:cryptographic-identity",
		"control:credential-isolation",
		"control:hardware-bound-credential",
	}
}

func scopedCredentialControlIDs() []string {
	return []string{
		"control:credential-helper",
		"control:short-lived-credential",
		"control:jit-access",
		"control:token-lifetime-policy",
	}
}

func inputControlIDs() []string {
	return []string{
		"control:input-isolation",
		"control:trusted-source-policy",
		"control:instruction-provenance",
		"control:untrusted-input-delimiting",
		"control:prompt-injection-filter",
		"control:input-validation",
	}
}

func hardInputControlIDs() []string {
	return []string{
		"control:input-isolation",
		"control:trusted-source-policy",
	}
}

func hasHardInputControl(c model.Collection) bool {
	return hasAnyControl(c, hardInputControlIDs()...)
}

func workloadControlIDs() []string {
	return []string{
		"control:identity-based-isolation",
		"control:named-caller-allowlist",
		"control:abac-policy",
		"control:network-segmentation",
		"control:tool-scope-policy",
	}
}

func hasStrongWorkloadAuthorization(c model.Collection) bool {
	callerOrCondition := hasAnyControl(c, "control:named-caller-allowlist", "control:abac-policy")
	isolationOrScope := hasAnyControl(c, "control:identity-based-isolation", "control:network-segmentation", "control:tool-scope-policy")
	return callerOrCondition && isolationOrScope
}

func hasWorkloadAuthorizationRisk(c model.Collection) bool {
	return hasApprovalRelevantSurface(c) || hasRiskyToolSurface(c) || hasStandingAuthorityRisk(c)
}

func continuousAuthorizationControlIDs() []string {
	return []string{
		"control:per-action-authorization",
		"control:continuous-authorization",
		"control:dynamic-privilege-scoping",
		"control:jit-elevation",
		"control:standing-access-denied",
		"control:automatic-access-revocation",
		"control:abac-policy",
		"control:tool-scope-policy",
		"control:jit-access",
		"control:token-lifetime-policy",
		"control:credential-revocation",
		"control:dynamic-access-reduction",
	}
}

func hasHardContinuousAuthorization(c model.Collection) bool {
	perAction := hasAnyControl(c, "control:per-action-authorization", "control:continuous-authorization")
	scoped := hasAnyControl(c, "control:dynamic-privilege-scoping", "control:jit-elevation", "control:jit-access", "control:standing-access-denied")
	revocable := hasAnyControl(c, "control:automatic-access-revocation", "control:credential-revocation", "control:dynamic-access-reduction")
	return perAction && scoped && revocable
}

func hasStandingAuthorityRisk(c model.Collection) bool {
	return hasAuthority(c, "authority:broad-local") ||
		hasAuthority(c, "authority:local-code-execution") ||
		hasAuthority(c, "authority:external-communication") ||
		hasAuthority(c, "authority:delegated-agent-authority") ||
		hasToolID(c, "tool:mcp-package-launch") ||
		hasToolID(c, "tool:agent-command-shell") ||
		hasBoundaryID(c, "boundary:credential-material")
}

func approvalControlIDs() []string {
	return []string{
		"control:approval-required",
		"control:audit-logging",
		"control:approval-log-evidence",
		"control:request-traceability",
		"control:observed-request-traceability",
	}
}

func hasApprovalGate(c model.Collection) bool {
	return hasAnyControl(c, "control:approval-required")
}

func hasApprovalAudit(c model.Collection) bool {
	return hasAnyControl(c, "control:audit-logging", "control:approval-log-evidence")
}

func hasHardApprovalBoundary(c model.Collection) bool {
	return hasApprovalGate(c) && hasApprovalAudit(c)
}

func hasApprovalRelevantSurface(c model.Collection) bool {
	return hasAuthority(c, "authority:broad-local") ||
		hasAuthority(c, "authority:local-code-execution") ||
		hasAuthority(c, "authority:external-communication") ||
		hasAuthority(c, "authority:delegated-agent-authority") ||
		(hasAuthority(c, "authority:file-read") && hasAnyBoundary(c, "boundary:secret-like-file", "boundary:developer-secret-boundary", "boundary:agent-private-context", "boundary:memory-credential-retention", "boundary:credential-material")) ||
		hasToolID(c, "tool:mcp-package-launch") ||
		hasToolID(c, "tool:agent-command-shell") ||
		hasToolID(c, "tool:agent-plugin-surface") ||
		hasToolID(c, "tool:agent-delegation")
}

func approvalRiskEvidence(c model.Collection) []model.ZeroTrustEvidence {
	out := authorityEvidenceByID(c,
		"authority:broad-local",
		"authority:local-code-execution",
		"authority:external-communication",
		"authority:delegated-agent-authority",
		"authority:file-read",
	)
	for _, tool := range c.Tools {
		switch tool.ID {
		case "tool:mcp-package-launch",
			"tool:agent-command-shell",
			"tool:agent-plugin-surface",
			"tool:agent-delegation":
			out = append(out, model.ZeroTrustEvidence{ID: tool.ID, Kind: "tool", Source: tool.Source, Summary: tool.Summary})
		}
	}
	return dedupeEvidence(out)
}

func resourceControlIDs() []string {
	return []string{
		"control:tool-rate-limit",
		"control:spend-limit",
		"control:loop-guard",
		"control:tool-timeout",
		"control:concurrency-limit",
		"control:resource-usage-audit",
		"control:tool-circuit-breaker",
		"control:behavioral-monitoring",
		"control:audit-logging",
		"control:telemetry-export",
	}
}

func hasHardResourceBoundary(c model.Collection) bool {
	bounded := hasAnyControl(c, "control:tool-rate-limit", "control:spend-limit", "control:concurrency-limit")
	stopCondition := hasAnyControl(c, "control:loop-guard", "control:tool-timeout", "control:tool-circuit-breaker", "control:session-termination", "control:dynamic-access-reduction")
	auditable := hasAnyControl(c, "control:resource-usage-audit", "control:behavioral-monitoring", "control:audit-logging", "control:telemetry-export")
	return bounded && stopCondition && auditable
}

func hasResourceRelevantSurface(c model.Collection) bool {
	return len(c.Runtimes) > 0 ||
		len(c.Tools) > 0 ||
		len(c.Authorities) > 0 ||
		hasAnyControl(c, resourceControlIDs()...)
}

func hasRunawayResourceRisk(c model.Collection) bool {
	return hasAuthority(c, "authority:broad-local") ||
		hasAuthority(c, "authority:local-code-execution") ||
		hasAuthority(c, "authority:external-communication") ||
		hasAuthority(c, "authority:delegated-agent-authority") ||
		hasToolID(c, "tool:mcp-package-launch") ||
		hasToolID(c, "tool:mcp-remote-server") ||
		hasToolID(c, "tool:agent-command-shell") ||
		hasToolID(c, "tool:agent-plugin-surface") ||
		hasToolID(c, "tool:agent-delegation")
}

func egressControlIDs() []string {
	out := append([]string{}, hardEgressControlIDs()...)
	out = append(out, softEgressControlIDs()...)
	return out
}

func hardEgressControlIDs() []string {
	return []string{
		"control:network-restricted",
		"control:egress-destination-allowlist",
		"control:webhook-allowlist",
		"control:per-tool-network-scope",
	}
}

func softEgressControlIDs() []string {
	return []string{
		"control:egress-content-filter",
		"control:egress-audit",
	}
}

func outputControlIDs() []string {
	return []string{
		"control:output-sensitive-data-filter",
		"control:output-redaction",
		"control:output-filter-logging",
		"control:semantic-output-analysis",
		"control:high-risk-output-review",
		"control:egress-content-filter",
		"control:audit-logging",
		"control:request-traceability",
		"control:telemetry-export",
	}
}

func sensitiveBoundaryControlIDs() []string {
	return []string{
		"control:deny-secret-read",
		"control:memory-isolation",
		"control:network-restricted",
		"control:egress-destination-allowlist",
		"control:webhook-allowlist",
		"control:per-tool-network-scope",
	}
}

func leastAgencyControlIDs() []string {
	return []string{
		"control:least-agency-policy",
		"control:deny-by-default-permissions",
		"control:scoped-permissions",
		"control:deny-secret-read",
		"control:mcp-reviewed-pinned",
		"control:network-restricted",
		"control:egress-destination-allowlist",
		"control:webhook-allowlist",
		"control:per-tool-network-scope",
		"control:tool-scope-policy",
		"control:tool-allowlist",
		"control:tool-argument-validation",
	}
}

func memoryControlIDs() []string {
	return []string{
		"control:context-retention",
		"control:memory-isolation",
		"control:context-integrity",
		"control:context-provenance",
		"control:deny-secret-read",
		"control:credential-isolation",
	}
}

func hasHardMemoryBoundary(c model.Collection) bool {
	isolated := hasAnyControl(c, "control:memory-isolation")
	retained := hasAnyControl(c, "control:context-retention")
	integrity := hasAnyControl(c, "control:context-integrity")
	provenance := hasAnyControl(c, "control:context-provenance")
	credentialSafe := !hasMemoryCredentialRetention(c) || hasAnyControl(c, "control:credential-isolation")
	return isolated && retained && integrity && provenance && credentialSafe
}

func hasMemoryRelevantSurface(c model.Collection) bool {
	return len(surfaceEvidenceByCategory(c, "memory")) > 0 ||
		len(surfaceEvidenceByCategory(c, "history-cache")) > 0 ||
		hasAnyBoundary(c, "boundary:agent-private-context", "boundary:memory-credential-retention")
}

func hasMemoryCredentialRetention(c model.Collection) bool {
	return hasBoundaryID(c, "boundary:memory-credential-retention")
}

func privateContextReachable(g model.Graph) bool {
	return hasEdge(g, "authority:file-read|reaches|boundary:agent-private-context") ||
		hasEdge(g, "authority:broad-local|reaches|boundary:agent-private-context") ||
		hasEdge(g, "authority:file-read|reaches|boundary:memory-credential-retention") ||
		hasEdge(g, "authority:broad-local|reaches|boundary:memory-credential-retention")
}

func hasBoundaryID(c model.Collection, id string) bool {
	for _, boundary := range c.Boundaries {
		if boundary.ID == id {
			return true
		}
	}
	return false
}

func hasAnyBoundary(c model.Collection, ids ...string) bool {
	for _, id := range ids {
		if hasBoundaryID(c, id) {
			return true
		}
	}
	return false
}

func hasAuthority(c model.Collection, id string) bool {
	for _, authority := range c.Authorities {
		if authority.ID == id {
			return true
		}
	}
	return false
}

func hasToolID(c model.Collection, id string) bool {
	for _, tool := range c.Tools {
		if tool.ID == id {
			return true
		}
	}
	return false
}

func hasRuntimeOrAuthority(c model.Collection) bool {
	return len(c.Runtimes) > 0 || len(c.Authorities) > 0
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

func authorityEvidenceByID(c model.Collection, ids ...string) []model.ZeroTrustEvidence {
	allow := map[string]bool{}
	for _, id := range ids {
		allow[id] = true
	}
	var out []model.ZeroTrustEvidence
	for _, authority := range c.Authorities {
		if len(allow) > 0 && !allow[authority.ID] {
			continue
		}
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

func toolIntegrityEvidence(c model.Collection) []model.ZeroTrustEvidence {
	var out []model.ZeroTrustEvidence
	for _, tool := range c.Tools {
		if tool.ID == "tool:agent-delegation" {
			continue
		}
		out = append(out, model.ZeroTrustEvidence{ID: tool.ID, Kind: "tool", Source: tool.Source, Summary: tool.Summary})
	}
	return dedupeEvidence(out)
}

func supplyChainEvidence(c model.Collection) []model.ZeroTrustEvidence {
	out := surfaceEvidenceByCategory(c, "supply-chain-bom")
	out = append(out, controlsEvidence(c, supplyChainControlIDs()...)...)
	return dedupeEvidence(out)
}

func delegationEvidence(c model.Collection) []model.ZeroTrustEvidence {
	var out []model.ZeroTrustEvidence
	for _, surface := range c.Surfaces {
		if surface.Category == "agent-delegation" {
			out = append(out, model.ZeroTrustEvidence{ID: surface.ID, Kind: surface.Category, Source: surface.Source, Summary: surface.Summary})
		}
	}
	for _, tool := range c.Tools {
		if tool.ID == "tool:agent-delegation" {
			out = append(out, model.ZeroTrustEvidence{ID: tool.ID, Kind: "tool", Source: tool.Source, Summary: tool.Summary})
		}
	}
	for _, authority := range c.Authorities {
		if authority.ID == "authority:delegated-agent-authority" {
			out = append(out, model.ZeroTrustEvidence{ID: authority.ID, Kind: "authority", Source: authority.Source, Summary: authority.Summary})
		}
	}
	for _, boundary := range c.Boundaries {
		if boundary.ID == "boundary:agent-delegation-boundary" {
			out = append(out, model.ZeroTrustEvidence{ID: boundary.ID, Kind: "boundary", Source: boundary.Source, Summary: boundary.Summary})
		}
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
	out = append(out, boundaryEvidence(c, "boundary:memory-credential-retention")...)
	return dedupeEvidence(out)
}

func configSurfaceEvidence(c model.Collection) []model.ZeroTrustEvidence {
	var out []model.ZeroTrustEvidence
	for _, surface := range c.Surfaces {
		if !configSurfaceCategory(surface.Category) {
			continue
		}
		out = append(out, model.ZeroTrustEvidence{ID: surface.ID, Kind: surface.Category, Source: surface.Source, Summary: surface.Summary})
	}
	for _, runtime := range c.Runtimes {
		out = append(out, model.ZeroTrustEvidence{ID: runtime.ID, Kind: "runtime", Source: runtime.Source, Summary: runtime.Summary})
	}
	return dedupeEvidence(out)
}

func configSurfaceCategory(category string) bool {
	switch category {
	case "runtime-config", "managed-remote-settings", "policy", "mcp-tool-config", "plugin-skill", "command-hook":
		return true
	default:
		return false
	}
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

func toolBoundaryEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		key := edge.Key()
		if edge.Type == "can_call" || edge.Type == "grants" ||
			key == "control:mcp-reviewed-pinned|restricts|tool:mcp-package-launch" ||
			key == "control:mcp-reviewed-pinned|restricts|boundary:developer-execution-boundary" {
			out = append(out, key)
		}
	}
	return uniqueStrings(out)
}

func toolIntegrityEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if edge.From == "tool:agent-delegation" ||
			edge.To == "tool:agent-delegation" ||
			edge.From == "authority:delegated-agent-authority" ||
			edge.To == "authority:delegated-agent-authority" {
			continue
		}
		if edge.Type == "can_call" || edge.Type == "grants" || (edge.Type == "restricts" && toolIntegrityControlID(edge.From)) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func supplyChainEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if edge.Type == "verifies" && supplyChainControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func outputEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if edge.Type == "filters" && outputControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func memoryEdges(g model.Graph) []string {
	out := edgesForNode(g, "boundary:agent-private-context")
	out = append(out, edgesForNode(g, "boundary:memory-credential-retention")...)
	for _, edge := range g.Edges {
		if edge.Type == "restricts" && memoryControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func authorizationEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if edge.Type == "authorizes" && authorizationControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func workloadEdges(g model.Graph) []string {
	out := edgesForTypes(g, "configures", "has_authority", "can_call")
	for _, edge := range g.Edges {
		if edge.Type == "authorizes" && workloadControlID(edge.From) {
			out = append(out, edge.Key())
		}
		if edge.Type == "restricts" && workloadControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func identityEdges(g model.Graph) []string {
	out := edgesForTypes(g, "configures", "has_authority", "can_call")
	for _, edge := range g.Edges {
		if (edge.Type == "identifies" || edge.Type == "scopes_credentials") && identityControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func approvalEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if edge.Type == "requires_approval" && approvalControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func observabilityEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if (edge.Type == "observes" || edge.Type == "traces") && observabilityControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func resourceEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if edge.Type == "limits" && resourceControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func workloadControlID(id string) bool {
	switch id {
	case "control:identity-based-isolation",
		"control:named-caller-allowlist",
		"control:abac-policy",
		"control:network-segmentation",
		"control:tool-scope-policy":
		return true
	default:
		return false
	}
}

func identityControlID(id string) bool {
	switch id {
	case "control:cryptographic-identity",
		"control:credential-isolation",
		"control:hardware-bound-credential",
		"control:credential-helper",
		"control:short-lived-credential",
		"control:jit-access",
		"control:token-lifetime-policy",
		"control:identity-lifecycle":
		return true
	default:
		return false
	}
}

func approvalControlID(id string) bool {
	switch id {
	case "control:approval-required":
		return true
	default:
		return false
	}
}

func observabilityControlID(id string) bool {
	switch id {
	case "control:audit-logging",
		"control:request-traceability",
		"control:observed-request-traceability",
		"control:agent-action-log-evidence",
		"control:tool-call-audit-evidence",
		"control:approval-log-evidence",
		"control:telemetry-export",
		"control:immutable-audit-log":
		return true
	default:
		return false
	}
}

func memoryControlID(id string) bool {
	switch id {
	case "control:context-retention",
		"control:memory-isolation",
		"control:context-integrity",
		"control:context-provenance",
		"control:deny-secret-read",
		"control:credential-isolation":
		return true
	default:
		return false
	}
}

func toolIntegrityControlID(id string) bool {
	switch id {
	case "control:tool-allowlist",
		"control:mcp-reviewed-pinned",
		"control:tool-descriptor-integrity",
		"control:tool-argument-validation",
		"control:tool-auth-required",
		"control:signed-tool-artifacts",
		"control:tool-deployment-verification":
		return true
	default:
		return false
	}
}

func authorizationControlID(id string) bool {
	switch id {
	case "control:per-action-authorization",
		"control:continuous-authorization",
		"control:dynamic-privilege-scoping",
		"control:jit-elevation",
		"control:standing-access-denied",
		"control:automatic-access-revocation",
		"control:abac-policy",
		"control:tool-scope-policy":
		return true
	default:
		return false
	}
}

func resourceControlID(id string) bool {
	switch id {
	case "control:tool-rate-limit",
		"control:spend-limit",
		"control:loop-guard",
		"control:tool-timeout",
		"control:concurrency-limit",
		"control:resource-usage-audit",
		"control:tool-circuit-breaker":
		return true
	default:
		return false
	}
}

func outputControlID(id string) bool {
	switch id {
	case "control:output-sensitive-data-filter",
		"control:output-redaction",
		"control:output-filter-logging",
		"control:semantic-output-analysis",
		"control:high-risk-output-review",
		"control:egress-content-filter":
		return true
	default:
		return false
	}
}

func supplyChainControlID(id string) bool {
	switch id {
	case "control:ai-bom",
		"control:model-provenance",
		"control:training-data-lineage",
		"control:dependency-health-scan",
		"control:provider-risk-review",
		"control:signed-ai-artifacts",
		"control:runtime-component-validation",
		"control:dependency-reachability-analysis":
		return true
	default:
		return false
	}
}

func delegationEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if edge.From == "tool:agent-delegation" ||
			edge.To == "tool:agent-delegation" ||
			edge.From == "authority:delegated-agent-authority" ||
			edge.To == "authority:delegated-agent-authority" ||
			edge.From == "boundary:agent-delegation-boundary" ||
			edge.To == "boundary:agent-delegation-boundary" ||
			(edge.Type == "restricts" && delegationControlID(edge.From)) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func responseEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if edge.Type == "restricts" && responseControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func governanceEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		if edge.Type == "governs" && governanceControlID(edge.From) {
			out = append(out, edge.Key())
		}
	}
	return uniqueStrings(out)
}

func responseControlID(id string) bool {
	switch id {
	case "control:automated-triage",
		"control:behavioral-monitoring",
		"control:session-termination",
		"control:credential-revocation",
		"control:containment-quarantine",
		"control:dynamic-access-reduction",
		"control:response-escalation":
		return true
	default:
		return false
	}
}

func governanceControlID(id string) bool {
	switch id {
	case "control:agent-inventory",
		"control:deployment-owner",
		"control:deployment-approval",
		"control:risk-assessment",
		"control:governance-audit",
		"control:shadow-ai-discovery":
		return true
	default:
		return false
	}
}

func delegationControlID(id string) bool {
	switch id {
	case "control:delegation-scope",
		"control:delegation-allowlist",
		"control:agent-to-agent-authorization",
		"control:origin-intent-verification",
		"control:delegated-credential-scope",
		"control:subagent-context-isolation":
		return true
	default:
		return false
	}
}

func configIntegrityEdges(g model.Graph) []string {
	out := []string{}
	for _, edge := range g.Edges {
		key := edge.Key()
		if edge.Type == "configures" || (edge.Type == "restricts" && configIntegrityControlID(edge.From)) {
			out = append(out, key)
		}
	}
	return uniqueStrings(out)
}

func configIntegrityControlID(id string) bool {
	switch id {
	case "control:config-version-control",
		"control:config-review-required",
		"control:signed-config",
		"control:config-deployment-verification",
		"control:managed-settings-enforced",
		"control:immutable-agent-runtime":
		return true
	default:
		return false
	}
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
