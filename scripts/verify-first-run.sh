#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${ARIADNE_BIN:-"$repo_root/bin/ariadne"}"
fixture="${ARIADNE_VERIFY_FIXTURE:-"$repo_root/ariadne-prove/testdata/realpath/combined-risk"}"
endpoint_fixture="${ARIADNE_VERIFY_ENDPOINT_FIXTURE:-"$repo_root/ariadne-prove/testdata/realpath/messy-ai-surfaces"}"
workdir="$(mktemp -d "${TMPDIR:-/private/tmp}/ariadne-first-run.XXXXXX")"

expect_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "$file"; then
    echo "missing expected text in $file:" >&2
    echo "  $needle" >&2
    echo "artifacts left in: $workdir" >&2
    exit 1
  fi
}

expect_not_contains() {
  local file="$1"
  local needle="$2"
  if grep -Fq -- "$needle" "$file"; then
    echo "unexpected text in $file:" >&2
    echo "  $needle" >&2
    echo "artifacts left in: $workdir" >&2
    exit 1
  fi
}

echo "Ariadne first-run verification"
echo "  bin: $bin"
echo "  fixture: $fixture"
echo "  endpoint fixture: $endpoint_fixture"
echo "  artifacts: $workdir"

assess_txt="$workdir/assess.txt"
assess_summary="$workdir/assess-summary.txt"
assess_json="$workdir/assess.json"
assess_html="$workdir/assess.html"
dashboard_html="$workdir/dashboard.html"
exposure_dashboard_html="$workdir/exposure-dashboard.html"
cases_txt="$workdir/cases.txt"
proofs_action="$workdir/proofs-action.txt"

"$bin" assess --path "$fixture" --out "$assess_summary"
"$bin" assess --path "$fixture" --format table --out "$assess_txt"
"$bin" assess --path "$fixture" --format json --out "$assess_json"
"$bin" assess --path "$fixture" --format html --out "$assess_html"
"$bin" dashboard --path "$fixture" --out "$dashboard_html"
"$bin" dashboard --path "$fixture" --view exposure --out "$exposure_dashboard_html"
"$bin" cases --path "$fixture" --out "$cases_txt"
"$bin" proofs --path "$fixture" --case case:input-trust-boundary --format action --out "$proofs_action"

summary_lines="$(wc -l < "$assess_summary" | tr -d '[:space:]')"
if [ "$summary_lines" -gt 90 ]; then
  echo "assessment summary is too long: $summary_lines lines" >&2
  echo "artifacts left in: $workdir" >&2
  exit 1
fi
expect_contains "$assess_summary" "Ariadne Summary"
expect_contains "$assess_summary" "Decision:"
expect_contains "$assess_summary" "Verdict: action required"
expect_contains "$assess_summary" "Start here: Egress And Output Boundary (case:egress-output-boundary)"
expect_contains "$assess_summary" "What was inspected:"
expect_contains "$assess_summary" "Risk basis:"
expect_contains "$assess_summary" "Normal capability:"
expect_contains "$assess_summary" "Signal quality:"
expect_contains "$assess_summary" "Actionable because:"
expect_contains "$assess_summary" "Noise filter:"
expect_contains "$assess_summary" "Decision rule: Capability alone is not exposure."
expect_contains "$assess_summary" "Lethal trifecta:"
expect_contains "$assess_summary" "Lethal trifecta present"
expect_contains "$assess_summary" "Exposure to untrusted content=present"
expect_contains "$assess_summary" "Evidence:"
expect_contains "$assess_summary" "Evidence files: .claude/settings.json; .codex/config.toml; .env"
expect_contains "$assess_summary" "Modeled/internal evidence: zt:control-strength"
expect_contains "$assess_summary" "Source references:"
expect_contains "$assess_summary" "Inspect:"
expect_contains "$assess_summary" "Path:"
expect_contains "$assess_summary" "Controls:"
expect_contains "$assess_summary" "Missing hard barrier: control:egress-destination-allowlist"
expect_contains "$assess_summary" "Present hard barrier: none observed for the current case"
expect_contains "$assess_summary" "Partial/friction control: none observed for the current case"
expect_contains "$assess_summary" "Unknown evidence: none for the current case"
expect_contains "$assess_summary" "Next action:"
expect_contains "$assess_summary" "Before proof:"
expect_contains "$assess_summary" "Export proof files:"
expect_contains "$assess_summary" "Full case proof bundle:"
expect_contains "$assess_summary" "proof-patches/surfaces/.ariadne/egress-policy.json"
expect_contains "$assess_summary" "proof-patches/surfaces/.ariadne/output-policy.json"
expect_contains "$assess_summary" "Review/apply bundle:"
expect_contains "$assess_summary" "cp surfaces/.ariadne/output-policy.json"
expect_contains "$assess_summary" "Rerun:"
expect_contains "$assess_summary" "After proof:"
expect_contains "$assess_summary" "Compare:"
expect_contains "$assess_summary" "Done when:"
expect_contains "$assess_summary" "More detail:"
expect_contains "$assess_summary" "--format table"
expect_not_contains "$assess_summary" "additional items in JSON"
expect_not_contains "$assess_summary" "more evidence reference(s) in JSON"

expect_contains "$assess_txt" "What was inspected:"
expect_contains "$assess_txt" "Decision:"
expect_contains "$assess_txt" "Verdict: action required"
expect_contains "$assess_txt" "Inspected: AI surfaces:"
expect_contains "$assess_txt" "Inspected: Runtime surface map:"
expect_contains "$assess_txt" "Risk basis:"
expect_contains "$assess_txt" "Evidence files: .claude/settings.json; .codex/config.toml; .env"
expect_contains "$assess_txt" "Modeled/internal evidence: zt:control-strength"
expect_contains "$assess_txt" "Evidence fact:"
expect_contains "$assess_txt" "Claude Code settings declare broad local authority"
expect_contains "$assess_txt" "Before proof:"
expect_contains "$assess_txt" "--out before-proof.json"
expect_contains "$assess_txt" "Proof command:"
expect_contains "$assess_txt" "After proof:"
expect_contains "$assess_txt" "--out after-proof.json"
expect_contains "$assess_txt" "Decision limit:"
expect_contains "$assess_txt" "Decision is derived from deterministic inventory"
expect_contains "$assess_txt" "Signal quality:"
expect_contains "$assess_txt" "Actionable because:"
expect_contains "$assess_txt" "Expected capability:"
expect_contains "$assess_txt" "Noise filter:"
expect_contains "$assess_txt" "Close/downgrade by:"
expect_contains "$assess_txt" "Decision rule: Capability alone is not exposure."
expect_contains "$assess_txt" "Lethal trifecta:"
expect_contains "$assess_txt" "Ingredient Exposure to untrusted content: present"
expect_contains "$assess_txt" "Ingredient Access to private data: present"
expect_contains "$assess_txt" "Ingredient Ability to externally communicate: present"
expect_contains "$assess_txt" "Break path: restrict external network communication and output destinations"
expect_contains "$assess_txt" "Signal triage:"
expect_contains "$assess_txt" "Normal capability:"
expect_contains "$assess_txt" "Missing hard barrier:"
expect_contains "$assess_txt" "Present hard barrier: none observed for the current case"
expect_contains "$assess_txt" "Partial/friction control: none observed for the current case"
expect_contains "$assess_txt" "Unknown evidence: none for the current case"
expect_contains "$assess_txt" "Control state:"
expect_contains "$assess_txt" "Current control: control:egress-destination-allowlist"
expect_contains "$assess_txt" "Current proof surface: .ariadne/egress-policy.json"
expect_contains "$assess_txt" "Missing hard-barrier evidence for control:egress-destination-allowlist"
expect_contains "$assess_txt" "Path to fix:"
expect_contains "$assess_txt" "Case lifecycle:"
expect_contains "$assess_txt" "Current step: open_proof_action"
expect_contains "$assess_txt" "Open Proof Action [current]:"
expect_contains "$assess_txt" "Save Baseline Proof [pending]:"
expect_contains "$assess_txt" "Review Or Apply Proof [pending]:"
expect_contains "$assess_txt" "Compare Proof State [pending]:"
expect_contains "$assess_txt" "Artifact: before-proof.json"
expect_contains "$assess_txt" "Artifact: case-compare.html"
expect_contains "$assess_txt" "Supported graph edge:"
expect_contains "$assess_txt" "boundary external destination (reaches)"
expect_contains "$assess_txt" "First action:"
expect_contains "$assess_txt" "Save baseline proof before changes:"
expect_contains "$assess_txt" "Review/apply generated proof bundle:"
expect_contains "$assess_txt" "Generated proof file: proof-patches/surfaces/.ariadne/egress-policy.json"
expect_contains "$assess_txt" "Generated bundle file: proof-patches/surfaces/.ariadne/egress-policy.json"
expect_contains "$assess_txt" "Generated bundle file: proof-patches/surfaces/.ariadne/output-policy.json"
expect_contains "$assess_txt" "Review/apply: cd proof-patches"
expect_contains "$assess_txt" "Review/apply bundle: cd proof-patches"
expect_contains "$assess_txt" "cp surfaces/.ariadne/output-policy.json"
expect_contains "$assess_txt" "Save after proof after rerun:"
expect_contains "$assess_txt" "Evidence files: .claude/settings.json; .codex/config.toml; .env"
expect_contains "$assess_txt" "Modeled/internal evidence: zt:control-strength"
expect_contains "$assess_txt" "Prove at: .ariadne/agent-policy.json; .ariadne/egress-policy.json; .ariadne/input-policy.json"
expect_contains "$assess_txt" "Compare loop:"
expect_contains "$assess_txt" "case-compare.html"

expect_contains "$assess_json" '"run_kind": "assess"'
expect_contains "$assess_json" '"decision"'
expect_contains "$assess_json" '"signal_noise"'
expect_contains "$assess_json" '"expected_capability"'
expect_contains "$assess_json" '"exposure_transition"'
expect_contains "$assess_json" '"downgrade_evidence"'
expect_contains "$assess_json" '"Capability alone is not exposure."'
expect_contains "$assess_json" '"signal_quality"'
expect_contains "$assess_json" '"lethal_trifecta"'
expect_contains "$assess_json" '"untrusted_content"'
expect_contains "$assess_json" '"private_data"'
expect_contains "$assess_json" '"external_communication"'
expect_contains "$assess_json" '"actionable_because"'
expect_contains "$assess_json" '"noise_filters"'
expect_contains "$assess_json" '"control_breakpoints"'
expect_contains "$assess_json" '"Capability alone is not exposure."'
expect_contains "$assess_json" '"inspection_summary"'
expect_contains "$assess_json" '"risk_reasons"'
expect_contains "$assess_json" '"evidence_refs"'
expect_contains "$assess_json" '"case_severity": "critical"'
expect_contains "$assess_json" '"case_state": "open"'
expect_contains "$assess_json" '"proof_command"'
expect_contains "$assess_json" '"before_proof_command"'
expect_contains "$assess_json" '"after_proof_command"'
expect_contains "$assess_json" '"present_hard_barriers"'
expect_contains "$assess_json" '"partial_or_friction_controls"'
expect_contains "$assess_json" '"unknown_evidence"'
expect_contains "$assess_json" '"evidence_gap_actions"'
expect_contains "$assess_json" '"done_criteria"'
expect_contains "$assess_json" '"control_state"'
expect_contains "$assess_json" '"current_control": "control:egress-destination-allowlist"'
expect_contains "$assess_json" '"current_proof_surface": ".ariadne/egress-policy.json"'
expect_contains "$assess_json" '"path_summary"'
expect_contains "$assess_json" '"graph_edges"'
expect_contains "$assess_json" 'authority:broad-local|reaches|boundary:external-destination'
expect_contains "$assess_json" '"generated_proof_path": "proof-patches/surfaces/.ariadne/egress-policy.json"'
expect_contains "$assess_json" '"generated_proof_paths"'
expect_contains "$assess_json" '"proof-patches/surfaces/.ariadne/output-policy.json"'
expect_contains "$assess_json" '"suggested_destination": ".ariadne/egress-policy.json"'
expect_contains "$assess_json" '"suggested_destinations"'
expect_contains "$assess_json" '".ariadne/output-policy.json"'
expect_contains "$assess_json" '"destination_path"'
expect_contains "$assess_json" '"apply_command": "cd proof-patches'
expect_contains "$assess_json" '"apply_commands"'
expect_contains "$assess_json" 'cp surfaces/.ariadne/output-policy.json'
expect_contains "$assess_json" '"first_action"'
expect_contains "$assess_json" '"operator_workbench"'
expect_contains "$assess_json" '"closure_loop"'
expect_contains "$assess_json" '"runbook"'
expect_contains "$assess_json" '"open_first"'
expect_contains "$assess_json" '"closure_workflow"'
expect_contains "$assess_json" '"save_baseline_proof"'
expect_contains "$assess_json" '"closure_decision"'
expect_contains "$assess_json" '"evidence_to_open"'
expect_contains "$assess_json" '"source_reference_workbench"'
expect_contains "$assess_json" '"inspect_command"'
expect_contains "$assess_json" '"content_inspectable"'
expect_contains "$assess_json" '"change_readout"'
expect_contains "$assess_json" '"case_lifecycle"'
expect_contains "$assess_json" '"current_step_id"'
expect_contains "$assess_json" '"open_proof_action"'
expect_contains "$assess_json" '"compare_state"'
expect_contains "$assess_json" '"generated_proof_paths"'
expect_contains "$assess_json" '"apply_commands"'
expect_contains "$assess_json" '"signal_details"'
expect_contains "$assess_json" '"normal_capability"'
expect_contains "$assess_json" '"missing_hard_barrier"'
expect_contains "$assess_json" '"proof_loop"'
expect_contains "$assess_json" '.claude/settings.json'
expect_contains "$assess_json" '.codex/config.toml'

expect_contains "$assess_html" "Ariadne Assessment"
expect_contains "$assess_html" "Source Reference Workbench"
expect_contains "$assess_html" "Exact files and lines to open first"
expect_contains "$assess_html" "Inspect command"
expect_contains "$assess_html" "sed -n"
expect_contains "$assess_html" "Operator Runbook"
expect_contains "$assess_html" "Open First"
expect_contains "$assess_html" "Do Next"
expect_contains "$assess_html" "Closure Workflow"
expect_contains "$assess_html" "Artifact: before-proof.json"
expect_contains "$assess_html" "Operator Workbench"
expect_contains "$assess_html" "Closure Loop"
expect_contains "$assess_html" "1. Current Case"
expect_contains "$assess_html" "2. Evidence To Open"
expect_contains "$assess_html" "3. Add Or Verify Proof"
expect_contains "$assess_html" "4. Verify The Change"
expect_contains "$assess_html" "5. Done Criteria"
expect_contains "$assess_html" "Change Readout"
expect_contains "$assess_html" "Case Lifecycle"
expect_contains "$assess_html" "Open Proof Action"
expect_contains "$assess_html" "Save Baseline Proof"
expect_contains "$assess_html" "Closure Decision"
expect_contains "$assess_html" "Compare Proof State"
expect_contains "$assess_html" "Decision Packet"
expect_contains "$assess_html" "Inspection Summary"
expect_contains "$assess_html" "Risk Basis"
expect_contains "$assess_html" "Evidence Facts"
expect_contains "$assess_html" "Proof Surface"
expect_contains "$assess_html" "Present Hard Barriers"
expect_contains "$assess_html" "Partial Or Friction Controls"
expect_contains "$assess_html" "Unknown Evidence"
expect_contains "$assess_html" "Evidence Gap Actions"
expect_contains "$assess_html" "Decision Limits"
expect_contains "$assess_html" "Signal Quality"
expect_contains "$assess_html" "Signal / Noise Evidence"
expect_contains "$assess_html" "Expected Capability"
expect_contains "$assess_html" "Exposure Transition"
expect_contains "$assess_html" "Downgrade Evidence"
expect_contains "$assess_html" "Lethal Trifecta"
expect_contains "$assess_html" "Exposure to untrusted content"
expect_contains "$assess_html" "Access to private data"
expect_contains "$assess_html" "Ability to externally communicate"
expect_contains "$assess_html" "Actionable Because"
expect_contains "$assess_html" "Noise Filters"
expect_contains "$assess_html" "Close Or Downgrade By"
expect_contains "$assess_html" "Capability alone is not exposure"
expect_contains "$assess_html" "Signal Triage"
expect_contains "$assess_html" "Control State"
expect_contains "$assess_html" "State Summary"
expect_contains "$assess_html" "Path To Fix"
expect_contains "$assess_html" "Graph Edges"
expect_contains "$assess_html" "Review / Apply Generated Proof"
expect_contains "$assess_html" "Review / Apply Full Proof Bundle"
expect_contains "$assess_html" "Proof Bundle Actions"
expect_contains "$assess_html" "Generated Artifact"
expect_contains "$assess_html" "Suggested Destination"
expect_contains "$assess_html" "Apply Command"
expect_contains "$assess_html" "Generated file: proof-patches/surfaces/.ariadne/egress-policy.json"
expect_contains "$assess_html" "Generated file: proof-patches/surfaces/.ariadne/output-policy.json"
expect_contains "$assess_html" 'data-copy-value="proof-patches/surfaces/.ariadne/egress-policy.json"'
expect_contains "$assess_html" 'data-copy-value="proof-patches/surfaces/.ariadne/output-policy.json"'
expect_contains "$assess_html" "Save baseline proof before changes"
expect_contains "$assess_html" "Save after proof after rerun"
expect_contains "$assess_html" "Proof Loop"
expect_contains "$assess_html" "copy-command"
expect_contains "$assess_html" "case-compare.html"

expect_contains "$dashboard_html" "Ariadne Assessment"
expect_contains "$dashboard_html" "Operator Runbook"
expect_contains "$dashboard_html" "Artifact: before-proof.json"
expect_contains "$dashboard_html" "Operator Cases"
expect_contains "$dashboard_html" "Export proof files"
expect_contains "$dashboard_html" "--patch-dir proof-patches"
expect_not_contains "$dashboard_html" "Ariadne Exposure Dashboard"
expect_contains "$exposure_dashboard_html" "Ariadne Exposure Dashboard"
expect_contains "$exposure_dashboard_html" "Exposure Paths"
expect_contains "$exposure_dashboard_html" "Facts Dive"

expect_contains "$cases_txt" "Ariadne operator case board:"
expect_contains "$cases_txt" "Evidence files: .claude/settings.json; .codex/config.toml; .env"
expect_contains "$cases_txt" "Modeled/internal evidence: zt:control-strength"
expect_contains "$cases_txt" "Prove at: .ariadne/agent-policy.json; .ariadne/egress-policy.json; .ariadne/input-policy.json"

expect_contains "$proofs_action" "Ariadne Proof Action"
expect_contains "$proofs_action" "Evidence files:"
expect_contains "$proofs_action" "Modeled/internal evidence:"
expect_contains "$proofs_action" "CLAUDE.md"
expect_contains "$proofs_action" "Proof to add or verify:"
expect_contains "$proofs_action" "Export suggested files:"
expect_contains "$proofs_action" "Compare loop:"

endpoint_action="$workdir/endpoint-assess-action.txt"
endpoint_json="$workdir/endpoint-assess.json"
endpoint_html="$workdir/endpoint-assess.html"
endpoint_cases="$workdir/endpoint-cases.txt"
self_summary="$workdir/self-summary.txt"
self_html="$workdir/self.html"
self_bundle="$workdir/ariadne-self"

"$bin" self --path "$endpoint_fixture" --bundle-dir "$self_bundle" --out "$self_summary"
"$bin" self --path "$endpoint_fixture" --format html --out "$self_html"
"$bin" assess --path "$endpoint_fixture" --mode endpoint --format action --out "$endpoint_action"
"$bin" assess --path "$endpoint_fixture" --mode endpoint --format json --out "$endpoint_json"
"$bin" assess --path "$endpoint_fixture" --mode endpoint --format html --out "$endpoint_html"
"$bin" cases --path "$endpoint_fixture" --mode endpoint --case case:least-agency-authority --out "$endpoint_cases"

expect_contains "$self_summary" "Ariadne Summary"
expect_contains "$self_summary" "Mode: endpoint"
expect_contains "$self_summary" "Decision:"
expect_contains "$self_summary" "Identity And Credentials"
expect_contains "$self_summary" "Source references:"
expect_contains "$self_summary" "Inspect:"
expect_contains "$self_summary" "Next action:"
expect_contains "$self_html" "Ariadne Assessment"
expect_contains "$self_html" "Operator Runbook"
expect_contains "$self_html" "Artifact: before-proof.json"
expect_contains "$self_html" "Operator Workbench"
expect_contains "$self_html" "Case Lifecycle"
expect_contains "$self_html" "Signal / Noise Evidence"
expect_contains "$self_html" "--mode endpoint"
expect_contains "$self_html" "Operator Cases"
expect_contains "$self_html" "Export proof files"

for bundle_file in assessment.txt assessment.json runbook.txt runbook.json operator-packet.txt operator-packet.json dashboard.html inventory.json cases.txt cases.json proof-action.txt proof-plan.json README.md manifest.json; do
  if [ ! -f "$self_bundle/$bundle_file" ]; then
    echo "missing self bundle file: $self_bundle/$bundle_file" >&2
    echo "artifacts left in: $workdir" >&2
    exit 1
  fi
done
expect_contains "$self_bundle/README.md" "Ariadne Self-Assessment Bundle"
expect_contains "$self_bundle/README.md" "What This Bundle Answers"
expect_contains "$self_bundle/README.md" "Suggested Review Order"
expect_contains "$self_bundle/README.md" "Proof Loop Commands"
expect_contains "$self_bundle/README.md" "runbook.txt"
expect_contains "$self_bundle/README.md" "runbook.json"
expect_contains "$self_bundle/README.md" "operator-packet.txt"
expect_contains "$self_bundle/README.md" "operator-packet.json"
expect_contains "$self_bundle/README.md" "dashboard.html"
expect_contains "$self_bundle/README.md" "proof-action.txt"
expect_contains "$self_bundle/README.md" "--patch-dir proof-patches"
expect_contains "$self_bundle/README.md" "ariadne compare --before before-proof.json --after after-proof.json --format html --out case-compare.html"
expect_contains "$self_bundle/README.md" "Limits And Privacy"
expect_contains "$self_bundle/README.md" "does not execute agents"
expect_contains "$self_bundle/README.md" "case:identity-credentials"
expect_contains "$self_bundle/assessment.json" '"run_kind": "assess"'
expect_contains "$self_bundle/assessment.json" '"signal_quality"'
expect_contains "$self_bundle/assessment.json" '"lethal_trifecta"'
expect_contains "$self_bundle/assessment.json" '"operator_packet"'
expect_contains "$self_bundle/assessment.json" '"operator_workbench"'
expect_contains "$self_bundle/assessment.json" '"closure_loop"'
expect_contains "$self_bundle/assessment.json" '"runbook"'
expect_contains "$self_bundle/assessment.json" '"open_first"'
expect_contains "$self_bundle/assessment.json" '"closure_workflow"'
expect_contains "$self_bundle/assessment.json" '"save_baseline_proof"'
expect_contains "$self_bundle/assessment.json" '"closure_decision"'
expect_contains "$self_bundle/assessment.json" '"source_reference_workbench"'
expect_contains "$self_bundle/assessment.json" '"inspect_command"'
expect_contains "$self_bundle/assessment.json" '"metadata_only"'
expect_contains "$self_bundle/assessment.json" '"top_case_id": "case:identity-credentials"'
expect_contains "$self_bundle/runbook.txt" "Ariadne Operator Runbook"
expect_contains "$self_bundle/runbook.txt" "case:identity-credentials"
expect_contains "$self_bundle/runbook.txt" "Open first:"
expect_contains "$self_bundle/runbook.txt" "Do next:"
expect_contains "$self_bundle/runbook.txt" "Save Baseline Proof"
expect_contains "$self_bundle/runbook.txt" "Add Or Verify Proof"
expect_contains "$self_bundle/runbook.txt" "Closure workflow:"
expect_contains "$self_bundle/runbook.json" '"available": true'
expect_contains "$self_bundle/runbook.json" '"case:identity-credentials"'
expect_contains "$self_bundle/runbook.json" '"current_step"'
expect_contains "$self_bundle/runbook.json" '"next_step"'
expect_contains "$self_bundle/runbook.json" '"open_first"'
expect_contains "$self_bundle/runbook.json" '"closure_workflow"'
expect_contains "$self_bundle/operator-packet.txt" "Ariadne Operator Packet"
expect_contains "$self_bundle/operator-packet.txt" "case:identity-credentials"
expect_contains "$self_bundle/operator-packet.txt" "Evidence to open:"
expect_contains "$self_bundle/operator-packet.txt" "Proof checkpoint:"
expect_contains "$self_bundle/operator-packet.txt" "Compare before and after:"
expect_not_contains "$self_bundle/operator-packet.txt" "additional items in JSON"
expect_not_contains "$self_bundle/operator-packet.txt" "more evidence source(s) in JSON"
expect_contains "$self_bundle/operator-packet.json" '"run_kind": "operator_packet"'
expect_contains "$self_bundle/operator-packet.json" '"source_run_kind": "assess"'
expect_contains "$self_bundle/operator-packet.json" '"operator_packet"'
expect_contains "$self_bundle/operator-packet.json" '"case_id": "case:identity-credentials"'
expect_contains "$self_bundle/operator-packet.json" '"compare_state"'
expect_contains "$self_bundle/inventory.json" '"run_kind": "inventory"'
expect_contains "$self_bundle/inventory.json" '.claude/settings.local.json'
expect_contains "$self_bundle/dashboard.html" "Ariadne Assessment"
expect_contains "$self_bundle/dashboard.html" "Source Reference Workbench"
expect_contains "$self_bundle/dashboard.html" "Exact files and lines to open first"
expect_contains "$self_bundle/dashboard.html" "Inspect command"
expect_contains "$self_bundle/dashboard.html" "sed -n"
expect_contains "$self_bundle/dashboard.html" "ls -ld"
expect_contains "$self_bundle/dashboard.html" "Operator Runbook"
expect_contains "$self_bundle/dashboard.html" "Open First"
expect_contains "$self_bundle/dashboard.html" "Do Next"
expect_contains "$self_bundle/dashboard.html" "Closure Workflow"
expect_contains "$self_bundle/dashboard.html" "Artifact: before-proof.json"
expect_contains "$self_bundle/dashboard.html" "Operator Workbench"
expect_contains "$self_bundle/dashboard.html" "Closure Loop"
expect_contains "$self_bundle/dashboard.html" "Save Baseline Proof"
expect_contains "$self_bundle/dashboard.html" "Closure Decision"
expect_contains "$self_bundle/dashboard.html" "Case Lifecycle"
expect_contains "$self_bundle/dashboard.html" "Signal / Noise Evidence"
expect_contains "$self_bundle/dashboard.html" "Signal Quality"
expect_contains "$self_bundle/dashboard.html" "Lethal Trifecta"
expect_contains "$self_bundle/proof-action.txt" "Ariadne Proof Action"
expect_contains "$self_bundle/proof-action.txt" "case:identity-credentials"
expect_contains "$self_bundle/proof-plan.json" '"run_kind": "proof_plan"'
expect_contains "$self_bundle/proof-plan.json" '"case_filter": "case:identity-credentials"'
expect_contains "$self_bundle/manifest.json" '"name": "README.md"'
expect_contains "$self_bundle/manifest.json" '"name": "manifest.json"'
expect_contains "$self_bundle/manifest.json" '"name": "runbook.txt"'
expect_contains "$self_bundle/manifest.json" '"name": "runbook.json"'
expect_contains "$self_bundle/manifest.json" '"name": "operator-packet.txt"'
expect_contains "$self_bundle/manifest.json" '"name": "operator-packet.json"'
expect_contains "$self_bundle/manifest.json" '"size_bytes"'
expect_contains "$self_bundle/manifest.json" '"sha256"'
expect_contains "$self_bundle/manifest.json" "intentionally not self-hashed"
expect_contains "$self_bundle/manifest.json" '"review_order"'
expect_contains "$self_bundle/manifest.json" '"proof_loop"'
expect_contains "$self_bundle/manifest.json" "--patch-dir proof-patches"
expect_contains "$self_bundle/manifest.json" '"limitations"'

expect_contains "$endpoint_action" "What was inspected:"
expect_contains "$endpoint_action" "Decision:"
expect_contains "$endpoint_action" "Verdict: action required"
expect_contains "$endpoint_action" "Inspected: AI surfaces:"
expect_contains "$endpoint_action" "Inspected: Runtime surface map:"
expect_contains "$endpoint_action" "Risk basis:"
expect_contains "$endpoint_action" "Evidence fact:"
expect_contains "$endpoint_action" "Before proof:"
expect_contains "$endpoint_action" "--out before-proof.json"
expect_contains "$endpoint_action" "Proof command:"
expect_contains "$endpoint_action" "After proof:"
expect_contains "$endpoint_action" "--out after-proof.json"
expect_contains "$endpoint_action" "Decision limit:"
expect_contains "$endpoint_action" "Decision is derived from deterministic inventory"
expect_contains "$endpoint_action" "Signal quality:"
expect_contains "$endpoint_action" "Lethal trifecta:"
expect_contains "$endpoint_action" "Noise filter:"
expect_contains "$endpoint_action" "Capability alone is not exposure."
expect_contains "$endpoint_action" "Signal triage:"
expect_contains "$endpoint_action" "Normal capability:"
expect_contains "$endpoint_action" "Missing hard barrier:"
expect_contains "$endpoint_action" "Present hard barrier: control:network-restricted"
expect_contains "$endpoint_action" "Control state:"
expect_contains "$endpoint_action" "Current control: control:credential-isolation"
expect_contains "$endpoint_action" "Current proof surface: .ariadne/identity-policy.json"
expect_contains "$endpoint_action" "Missing hard-barrier evidence for control:credential-isolation"
expect_contains "$endpoint_action" "Path to fix:"
expect_contains "$endpoint_action" "Case lifecycle:"
expect_contains "$endpoint_action" "Current step: open_proof_action"
expect_contains "$endpoint_action" "Open Proof Action [current]:"
expect_contains "$endpoint_action" "Save Baseline Proof [pending]:"
expect_contains "$endpoint_action" "Review Or Apply Proof [pending]:"
expect_contains "$endpoint_action" "Compare Proof State [pending]:"
expect_contains "$endpoint_action" "Artifact: before-proof.json"
expect_contains "$endpoint_action" "Artifact: case-compare.html"
expect_contains "$endpoint_action" "Supported graph edge:"
expect_contains "$endpoint_action" "boundary external destination (reaches)"
expect_contains "$endpoint_action" "Save baseline proof before changes:"
expect_contains "$endpoint_action" "Review/apply generated proof bundle:"
expect_contains "$endpoint_action" "Generated file: proof-patches/surfaces/.ariadne/identity-policy.json"
expect_contains "$endpoint_action" "Review/apply: cd proof-patches"
expect_contains "$endpoint_action" "Save after proof after rerun:"
expect_contains "$endpoint_action" "Identity And Credentials"
expect_contains "$endpoint_action" "Evidence files:"
expect_contains "$endpoint_action" ".aider.chat.history.md"
expect_contains "$endpoint_action" ".aider.conf.yml"
expect_contains "$endpoint_action" ".claude/paste-cache"
expect_contains "$endpoint_action" ".claude/settings.local.json"
expect_contains "$endpoint_action" ".codex/config.toml"
expect_contains "$endpoint_action" ".continue/config.json"
expect_contains "$endpoint_action" ".cursor/mcp.json"
expect_contains "$endpoint_action" ".vscode/settings.json"
expect_contains "$endpoint_action" ".cline/mcp.json"
expect_contains "$endpoint_action" ".roo/cache"
expect_contains "$endpoint_action" ".gemini/settings.json"
expect_contains "$endpoint_action" "Proof loop:"
expect_contains "$endpoint_action" "case-compare.html"

expect_contains "$endpoint_json" '"mode": "endpoint"'
expect_contains "$endpoint_json" '"decision"'
expect_contains "$endpoint_json" '"signal_noise"'
expect_contains "$endpoint_json" '"expected_capability"'
expect_contains "$endpoint_json" '"exposure_transition"'
expect_contains "$endpoint_json" '"downgrade_evidence"'
expect_contains "$endpoint_json" '"signal_quality"'
expect_contains "$endpoint_json" '"lethal_trifecta"'
expect_contains "$endpoint_json" '"noise_filters"'
expect_contains "$endpoint_json" '"inspection_summary"'
expect_contains "$endpoint_json" '"risk_reasons"'
expect_contains "$endpoint_json" '"evidence_refs"'
expect_contains "$endpoint_json" '"proof_command"'
expect_contains "$endpoint_json" '"before_proof_command"'
expect_contains "$endpoint_json" '"after_proof_command"'
expect_contains "$endpoint_json" '"present_hard_barriers"'
expect_contains "$endpoint_json" '"partial_or_friction_controls"'
expect_contains "$endpoint_json" '"unknown_evidence"'
expect_contains "$endpoint_json" '"evidence_gap_actions"'
expect_contains "$endpoint_json" '"done_criteria"'
expect_contains "$endpoint_json" '"top_case_id": "case:identity-credentials"'
expect_contains "$endpoint_json" '"control_state"'
expect_contains "$endpoint_json" '"current_control": "control:credential-isolation"'
expect_contains "$endpoint_json" '"current_proof_surface": ".ariadne/identity-policy.json"'
expect_contains "$endpoint_json" '"path_summary"'
expect_contains "$endpoint_json" '"graph_edges"'
expect_contains "$endpoint_json" 'authority:broad-local|reaches|boundary:external-destination'
expect_contains "$endpoint_json" '"generated_proof_path": "proof-patches/surfaces/.ariadne/identity-policy.json"'
expect_contains "$endpoint_json" '"suggested_destination": ".ariadne/identity-policy.json"'
expect_contains "$endpoint_json" '"destination_path"'
expect_contains "$endpoint_json" '"apply_command": "cd proof-patches'
expect_contains "$endpoint_json" '"present_hard_barriers"'
expect_contains "$endpoint_json" 'control:network-restricted'
expect_contains "$endpoint_json" '"operator_workbench"'
expect_contains "$endpoint_json" '"closure_loop"'
expect_contains "$endpoint_json" '"runbook"'
expect_contains "$endpoint_json" '"open_first"'
expect_contains "$endpoint_json" '"closure_workflow"'
expect_contains "$endpoint_json" '"save_baseline_proof"'
expect_contains "$endpoint_json" '"closure_decision"'
expect_contains "$endpoint_json" '"evidence_to_open"'
expect_contains "$endpoint_json" '"source_reference_workbench"'
expect_contains "$endpoint_json" '"inspect_command"'
expect_contains "$endpoint_json" '"metadata_only"'
expect_contains "$endpoint_json" '"change_readout"'
expect_contains "$endpoint_json" '"case_lifecycle"'
expect_contains "$endpoint_json" '"current_step_id"'
expect_contains "$endpoint_json" '"open_proof_action"'
expect_contains "$endpoint_json" '"compare_state"'
expect_contains "$endpoint_json" '.claude/.mcp.json'
expect_contains "$endpoint_json" '.vscode/mcp.json'
expect_contains "$endpoint_json" '.cline/mcp.json'
expect_contains "$endpoint_json" '.roo/mcp.json'
expect_contains "$endpoint_json" '.gemini/settings.json'

expect_contains "$endpoint_html" "Ariadne Assessment"
expect_contains "$endpoint_html" "Source Reference Workbench"
expect_contains "$endpoint_html" "Exact files and lines to open first"
expect_contains "$endpoint_html" "Inspect command"
expect_contains "$endpoint_html" "sed -n"
expect_contains "$endpoint_html" "ls -ld"
expect_contains "$endpoint_html" "Operator Runbook"
expect_contains "$endpoint_html" "Open First"
expect_contains "$endpoint_html" "Do Next"
expect_contains "$endpoint_html" "Closure Workflow"
expect_contains "$endpoint_html" "Artifact: before-proof.json"
expect_contains "$endpoint_html" "Operator Workbench"
expect_contains "$endpoint_html" "Closure Loop"
expect_contains "$endpoint_html" "1. Current Case"
expect_contains "$endpoint_html" "2. Evidence To Open"
expect_contains "$endpoint_html" "3. Add Or Verify Proof"
expect_contains "$endpoint_html" "4. Verify The Change"
expect_contains "$endpoint_html" "5. Done Criteria"
expect_contains "$endpoint_html" "Change Readout"
expect_contains "$endpoint_html" "Case Lifecycle"
expect_contains "$endpoint_html" "Open Proof Action"
expect_contains "$endpoint_html" "Save Baseline Proof"
expect_contains "$endpoint_html" "Closure Decision"
expect_contains "$endpoint_html" "Compare Proof State"
expect_contains "$endpoint_html" "Decision Packet"
expect_contains "$endpoint_html" "Inspection Summary"
expect_contains "$endpoint_html" "Risk Basis"
expect_contains "$endpoint_html" "Evidence Facts"
expect_contains "$endpoint_html" "Proof Surface"
expect_contains "$endpoint_html" "Present Hard Barriers"
expect_contains "$endpoint_html" "Partial Or Friction Controls"
expect_contains "$endpoint_html" "Unknown Evidence"
expect_contains "$endpoint_html" "Evidence Gap Actions"
expect_contains "$endpoint_html" "Decision Limits"
expect_contains "$endpoint_html" "Signal Quality"
expect_contains "$endpoint_html" "Signal / Noise Evidence"
expect_contains "$endpoint_html" "Expected Capability"
expect_contains "$endpoint_html" "Exposure Transition"
expect_contains "$endpoint_html" "Downgrade Evidence"
expect_contains "$endpoint_html" "Lethal Trifecta"
expect_contains "$endpoint_html" "Noise Filters"
expect_contains "$endpoint_html" "Signal Triage"
expect_contains "$endpoint_html" "Control State"
expect_contains "$endpoint_html" "State Summary"
expect_contains "$endpoint_html" "Path To Fix"
expect_contains "$endpoint_html" "Graph Edges"
expect_contains "$endpoint_html" "Review / Apply Generated Proof"
expect_contains "$endpoint_html" "Proof Bundle Actions"
expect_contains "$endpoint_html" "Generated Artifact"
expect_contains "$endpoint_html" "Suggested Destination"
expect_contains "$endpoint_html" "Apply Command"
expect_contains "$endpoint_html" "Generated file: proof-patches/surfaces/.ariadne/identity-policy.json"
expect_contains "$endpoint_html" 'data-copy-value="proof-patches/surfaces/.ariadne/identity-policy.json"'
expect_contains "$endpoint_html" "Save baseline proof before changes"
expect_contains "$endpoint_html" "Save after proof after rerun"
expect_contains "$endpoint_html" "Proof Loop"
expect_contains "$endpoint_html" ".claude/.mcp.json"
expect_contains "$endpoint_html" ".vscode/mcp.json"
expect_contains "$endpoint_html" ".cline/mcp.json"
expect_contains "$endpoint_html" ".roo/mcp.json"
expect_contains "$endpoint_html" ".gemini/settings.json"
expect_contains "$endpoint_html" "copy-command"

expect_contains "$endpoint_cases" "Case: case:least-agency-authority"
expect_contains "$endpoint_cases" "Evidence files:"
expect_contains "$endpoint_cases" ".claude/.mcp.json"
expect_contains "$endpoint_cases" ".codex/config.toml"
expect_contains "$endpoint_cases" ".roo/mcp.json"
expect_contains "$endpoint_cases" ".gemini/settings.json"
expect_contains "$endpoint_cases" "Prove at:"

endpoint_loop="$workdir/endpoint-identity-loop"
cp -R "$endpoint_fixture" "$endpoint_loop"

endpoint_before_json="$workdir/endpoint-before-proof.json"
endpoint_after_json="$workdir/endpoint-after-proof.json"
endpoint_after_case="$workdir/endpoint-after-case.txt"
endpoint_compare_txt="$workdir/endpoint-compare.txt"
endpoint_inventory_after="$workdir/endpoint-inventory-after.json"
endpoint_export_dir="$workdir/endpoint-proof-patches"
endpoint_export_log="$workdir/endpoint-proof-export.log"

"$bin" proofs --path "$endpoint_loop" --mode endpoint --case case:identity-credentials --format json --out "$endpoint_before_json"
"$bin" proofs --path "$endpoint_loop" --mode endpoint --case case:identity-credentials --patch-dir "$endpoint_export_dir" --format action --out "$workdir/endpoint-proof-export-action.txt" 2> "$endpoint_export_log"

expect_contains "$endpoint_export_log" "Generated proof files:"
expect_contains "$endpoint_export_log" "identity-policy.json"
expect_contains "$endpoint_export_log" "control:credential-isolation"
expect_contains "$endpoint_export_log" "control:cryptographic-identity"

mkdir -p "$endpoint_loop/.ariadne"
cp "$endpoint_export_dir/surfaces/.ariadne/identity-policy.json" "$endpoint_loop/.ariadne/identity-policy.json"

"$bin" cases --path "$endpoint_loop" --mode endpoint --case case:identity-credentials --out "$endpoint_after_case"
"$bin" proofs --path "$endpoint_loop" --mode endpoint --case case:identity-credentials --format json --out "$endpoint_after_json"
"$bin" compare --before "$endpoint_before_json" --after "$endpoint_after_json" --out "$endpoint_compare_txt"
"$bin" inventory --path "$endpoint_loop" --mode endpoint --format json --out "$endpoint_inventory_after"

expect_contains "$endpoint_after_case" "State: closed"
expect_contains "$endpoint_after_case" "0 missing hard-barrier controls"
expect_contains "$endpoint_after_case" ".ariadne/identity-policy.json"

expect_contains "$endpoint_compare_txt" "Verdict: proof succeeded"
expect_contains "$endpoint_compare_txt" "open -> closed"
expect_contains "$endpoint_compare_txt" "Missing controls before:"
expect_contains "$endpoint_compare_txt" "Observed controls after:"
expect_contains "$endpoint_compare_txt" "Proof patches: 5 -> 0"
expect_contains "$endpoint_compare_txt" ".ariadne/identity-policy.json"

expect_contains "$endpoint_inventory_after" '"control:credential-isolation"'
expect_contains "$endpoint_inventory_after" '"control:cryptographic-identity"'
expect_contains "$endpoint_inventory_after" '"control:short-lived-credential"'

loop_target="$workdir/combined-risk"
cp -R "$fixture" "$loop_target"

before_json="$workdir/before-proof.json"
after_json="$workdir/after-proof.json"
after_case="$workdir/after-case.txt"
compare_txt="$workdir/compare.txt"
compare_json="$workdir/compare.json"
compare_html="$workdir/compare.html"
export_dir="$workdir/proof-patches"
export_log="$workdir/proof-export.log"

"$bin" proofs --path "$loop_target" --case case:egress-output-boundary --format json --out "$before_json"
"$bin" proofs --path "$loop_target" --case case:egress-output-boundary --patch-dir "$export_dir" --format action --out "$workdir/proof-export-action.txt" 2> "$export_log"

expect_contains "$export_log" "Generated proof files:"
expect_contains "$export_log" "Review/apply:"
expect_contains "$export_log" "egress-policy.json"
expect_contains "$export_log" "output-policy.json"

mkdir -p "$loop_target/.ariadne"
cp "$export_dir/surfaces/.ariadne/egress-policy.json" "$loop_target/.ariadne/egress-policy.json"
cp "$export_dir/surfaces/.ariadne/output-policy.json" "$loop_target/.ariadne/output-policy.json"

"$bin" cases --path "$loop_target" --case case:egress-output-boundary --out "$after_case"
"$bin" proofs --path "$loop_target" --case case:egress-output-boundary --format json --out "$after_json"
"$bin" compare --before "$before_json" --after "$after_json" --out "$compare_txt"
"$bin" compare --before "$before_json" --after "$after_json" --format json --out "$compare_json"
"$bin" compare --before "$before_json" --after "$after_json" --format html --out "$compare_html"

expect_contains "$after_case" "State: closed"
expect_contains "$after_case" "0 missing hard-barrier controls"
expect_contains "$after_case" ".ariadne/egress-policy.json"
expect_contains "$after_case" ".ariadne/output-policy.json"

expect_contains "$compare_txt" "Decision:"
expect_contains "$compare_txt" "Verdict: proof succeeded"
expect_contains "$compare_txt" "Readout: Proof worked"
expect_contains "$compare_txt" "open -> closed"
expect_contains "$compare_txt" "Missing controls before:"
expect_contains "$compare_txt" "Observed controls after:"
expect_contains "$compare_txt" "Proof patches: 5 -> 0"
expect_contains "$compare_txt" "Added evidence:"
expect_contains "$compare_txt" ".ariadne/egress-policy.json"
expect_contains "$compare_txt" ".ariadne/output-policy.json"

expect_contains "$compare_json" '"decision"'
expect_contains "$compare_json" '"status": "proof_succeeded"'
expect_contains "$compare_json" '"top_case_id": "case:egress-output-boundary"'
expect_contains "$compare_json" '"proof_patches_before": 5'
expect_contains "$compare_json" '"proof_patches_after": 0'
expect_contains "$compare_json" '"added_evidence_sources"'
expect_contains "$compare_json" '"before_state": "open"'
expect_contains "$compare_json" '"after_state": "closed"'
expect_contains "$compare_json" '"added_evidence_refs"'
expect_contains "$compare_html" "Compare Decision"
expect_contains "$compare_html" "PROOF SUCCEEDED"
expect_contains "$compare_html" "CLOSED"
expect_contains "$compare_html" "open"
expect_contains "$compare_html" "closed"
expect_contains "$compare_html" "Missing controls before"
expect_contains "$compare_html" "Observed controls after"
expect_contains "$compare_html" ".ariadne/egress-policy.json"
expect_contains "$compare_html" ".ariadne/output-policy.json"
expect_contains "$compare_html" 'data-copy-value=".ariadne/egress-policy.json"'
expect_contains "$compare_html" 'data-copy-value=".ariadne/output-policy.json"'
expect_contains "$compare_html" "Copy path</button>"

echo "First-run verification passed"
echo "  artifacts: $workdir"
