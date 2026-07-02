package model

import "time"

const SchemaVersion = "ariadne.report/v1"

type Status string

const (
	StatusExposed      Status = "exposed"
	StatusProtected    Status = "protected"
	StatusInconclusive Status = "inconclusive"
)

type ProofMode string

const (
	ProofInferred  ProofMode = "inferred"
	ProofSimulated ProofMode = "simulated"
	ProofLiveLab   ProofMode = "live_lab"
)

type ObservationStatus string

const (
	ObservationNotAttempted   ObservationStatus = "not_attempted"
	ObservationAttempted      ObservationStatus = "attempted"
	ObservationBlocked        ObservationStatus = "blocked"
	ObservationSucceededInLab ObservationStatus = "succeeded_in_lab"
	ObservationInconclusive   ObservationStatus = "inconclusive"
	ObservationError          ObservationStatus = "error"
)

type Manifest struct {
	ID           string         `json:"id"`
	Title        string         `json:"title"`
	Persona      string         `json:"persona"`
	UserQuestion string         `json:"user_question"`
	Runtime      string         `json:"runtime"`
	Mode         string         `json:"mode"`
	World        World          `json:"world"`
	Expected     ExpectedResult `json:"expected"`
}

type World struct {
	RepoPath string `json:"repo_path"`
	HomePath string `json:"home_path"`
}

type ExpectedResult struct {
	Status                  Status    `json:"status"`
	ProofMode               ProofMode `json:"proof_mode"`
	RequiredNodes           []string  `json:"required_nodes"`
	RequiredEdges           []string  `json:"required_edges"`
	ControlsBreakPath       []string  `json:"controls_break_path"`
	RedactionMustNotContain []string  `json:"redaction_must_not_contain,omitempty"`
}

type Story struct {
	Dir      string   `json:"-"`
	Manifest Manifest `json:"manifest"`
}

type Report struct {
	SchemaVersion  string           `json:"schema_version"`
	RunID          string           `json:"run_id"`
	GeneratedAt    time.Time        `json:"generated_at"`
	RunKind        string           `json:"run_kind"`
	TargetPath     string           `json:"target_path,omitempty"`
	Story          StorySummary     `json:"story"`
	Expected       ExpectedResult   `json:"expected"`
	Matched        bool             `json:"matched"`
	Mismatches     []string         `json:"mismatches,omitempty"`
	Exposure       ExposureResult   `json:"exposure"`
	Exposures      []ExposureResult `json:"exposures,omitempty"`
	Interpretation Interpretation   `json:"interpretation"`
	ZeroTrust      ZeroTrust        `json:"zero_trust"`
	Graph          Graph            `json:"graph"`
	Evidence       []Evidence       `json:"evidence"`
	Redaction      RedactionInfo    `json:"redaction"`
	Warnings       []string         `json:"warnings,omitempty"`
	Limitations    []string         `json:"limitations"`
}

type ArchitectureReport struct {
	SchemaVersion     string                      `json:"schema_version"`
	RunID             string                      `json:"run_id"`
	GeneratedAt       time.Time                   `json:"generated_at"`
	TargetPath        string                      `json:"target_path,omitempty"`
	Mode              string                      `json:"mode"`
	Agent             string                      `json:"agent"`
	FrameworkVersion  string                      `json:"framework_version"`
	StatusFilter      string                      `json:"status_filter"`
	Summary           ZeroTrustSummary            `json:"summary"`
	OverallSummary    ZeroTrustSummary            `json:"overall_summary"`
	EvidenceCoverage  ZeroTrustCoverage           `json:"evidence_coverage"`
	EvidencePlan      []ArchitectureEvidencePlan  `json:"evidence_plan"`
	FrameworkCoverage []ArchitectureFrameworkArea `json:"framework_coverage"`
	Maturity          ZeroTrustMaturity           `json:"maturity"`
	BoundaryCoverage  []ArchitectureBoundary      `json:"boundary_coverage"`
	Flaws             []ZeroTrustArchitecture     `json:"flaws"`
	ClosurePlan       []ArchitectureClosure       `json:"closure_plan"`
	ClosureFamilies   []ArchitectureClosureFamily `json:"closure_families"`
	Redaction         RedactionInfo               `json:"redaction"`
	Limitations       []string                    `json:"limitations"`
}

type ArchitectureScanReport struct {
	SchemaVersion     string                      `json:"schema_version"`
	RunID             string                      `json:"run_id"`
	GeneratedAt       time.Time                   `json:"generated_at"`
	RunKind           string                      `json:"run_kind"`
	TargetsFile       string                      `json:"targets_file,omitempty"`
	Mode              string                      `json:"mode"`
	Agent             string                      `json:"agent"`
	StatusFilter      string                      `json:"status_filter"`
	Summary           ArchitectureScanSummary     `json:"summary"`
	EvidencePlan      []ArchitectureEvidencePlan  `json:"evidence_plan"`
	FrameworkCoverage []ArchitectureFrameworkArea `json:"framework_coverage"`
	BoundaryCoverage  []ArchitectureBoundary      `json:"boundary_coverage"`
	Groups            []ArchitectureFlawGroup     `json:"groups"`
	ClosurePlan       []ArchitectureClosure       `json:"closure_plan"`
	ClosureFamilies   []ArchitectureClosureFamily `json:"closure_families"`
	Targets           []ArchitectureTargetReport  `json:"targets"`
	Redaction         RedactionInfo               `json:"redaction"`
	Limitations       []string                    `json:"limitations"`
}

type ArchitectureScanSummary struct {
	Targets       int `json:"targets"`
	Completed     int `json:"completed"`
	Errors        int `json:"errors"`
	MatchingFlaws int `json:"matching_flaws"`
	DistinctFlaws int `json:"distinct_flaws"`
	Breaking      int `json:"breaking"`
	Controlled    int `json:"controlled"`
	Unknown       int `json:"unknown"`
	NotObserved   int `json:"not_observed"`
}

type ControlCatalogReport struct {
	SchemaVersion     string                       `json:"schema_version"`
	RunID             string                       `json:"run_id"`
	GeneratedAt       time.Time                    `json:"generated_at"`
	RunKind           string                       `json:"run_kind"`
	TargetPath        string                       `json:"target_path,omitempty"`
	TargetsFile       string                       `json:"targets_file,omitempty"`
	Mode              string                       `json:"mode"`
	Agent             string                       `json:"agent"`
	StatusFilter      string                       `json:"status_filter"`
	CaseFilter        string                       `json:"case_filter,omitempty"`
	Summary           ControlCatalogSummary        `json:"summary"`
	Controls          []ArchitectureClosure        `json:"controls"`
	Families          []ArchitectureClosureFamily  `json:"families"`
	OperatorCases     []ControlOperatorCase        `json:"operator_cases"`
	Workstreams       []ControlBreakPathWorkstream `json:"workstreams"`
	ProofSpecs        []ControlProofSpec           `json:"proof_specs"`
	VerificationTasks []ControlVerificationTask    `json:"verification_tasks"`
	Redaction         RedactionInfo                `json:"redaction"`
	Limitations       []string                     `json:"limitations"`
}

type ProofPlanReport struct {
	SchemaVersion      string                `json:"schema_version"`
	RunID              string                `json:"run_id"`
	GeneratedAt        time.Time             `json:"generated_at"`
	RunKind            string                `json:"run_kind"`
	TargetPath         string                `json:"target_path,omitempty"`
	TargetsFile        string                `json:"targets_file,omitempty"`
	Mode               string                `json:"mode"`
	Agent              string                `json:"agent"`
	StatusFilter       string                `json:"status_filter"`
	CaseFilter         string                `json:"case_filter,omitempty"`
	Summary            ProofPlanSummary      `json:"summary"`
	Cases              []ControlOperatorCase `json:"cases"`
	ProofPatches       []ControlProofPatch   `json:"proof_patches"`
	EvidenceReferences []EvidenceReference   `json:"evidence_refs"`
	RerunCommands      []string              `json:"rerun_commands"`
	CompareCommands    []string              `json:"compare_commands"`
	PatchExportCommand string                `json:"patch_export_command"`
	SuccessCriteria    []string              `json:"success_criteria"`
	Workflow           []ProofWorkflowStep   `json:"workflow"`
	Redaction          RedactionInfo         `json:"redaction"`
	Limitations        []string              `json:"limitations"`
}

type ProofWorkflowStep struct {
	ID                 string              `json:"id"`
	Title              string              `json:"title"`
	Summary            string              `json:"summary"`
	Commands           []string            `json:"commands"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	ProofSurfaces      []string            `json:"proof_surfaces"`
	SuccessCriteria    []string            `json:"success_criteria"`
	Limitations        []string            `json:"limitations"`
}

type ProofPlanSummary struct {
	Cases              int `json:"cases"`
	ProofPatches       int `json:"proof_patches"`
	EvidenceReferences int `json:"evidence_refs"`
	Controls           int `json:"controls"`
	Targets            int `json:"targets"`
	Flaws              int `json:"flaws"`
}

type CaseCompareReport struct {
	SchemaVersion string              `json:"schema_version"`
	RunKind       string              `json:"run_kind"`
	BeforeSource  string              `json:"before_source"`
	AfterSource   string              `json:"after_source"`
	Summary       CaseCompareSummary  `json:"summary"`
	Decision      CaseCompareDecision `json:"decision"`
	Outcome       CaseCompareOutcome  `json:"outcome"`
	Cases         []CaseCompareResult `json:"cases"`
	Limitations   []string            `json:"limitations"`
}

type CaseCompareSummary struct {
	Cases        int `json:"cases"`
	Closed       int `json:"closed"`
	Reopened     int `json:"reopened"`
	StayedOpen   int `json:"stayed_open"`
	StayedClosed int `json:"stayed_closed"`
	Changed      int `json:"changed"`
	Added        int `json:"added"`
	Removed      int `json:"removed"`
}

type CaseCompareDecision struct {
	Status               string   `json:"status"`
	Headline             string   `json:"headline"`
	TopCaseID            string   `json:"top_case_id,omitempty"`
	TopCaseTitle         string   `json:"top_case_title,omitempty"`
	TopCaseSeverity      string   `json:"top_case_severity,omitempty"`
	TopCaseDisposition   string   `json:"top_case_disposition,omitempty"`
	BeforeState          string   `json:"before_state,omitempty"`
	AfterState           string   `json:"after_state,omitempty"`
	AfterOpen            int      `json:"after_open"`
	AfterClosed          int      `json:"after_closed"`
	MaterialChanges      int      `json:"material_changes"`
	ProofPatchesBefore   int      `json:"proof_patches_before"`
	ProofPatchesAfter    int      `json:"proof_patches_after"`
	AddedControls        []string `json:"added_controls"`
	AddedEvidenceSources []string `json:"added_evidence_sources"`
	OpenCases            []string `json:"open_cases"`
	ClosedCases          []string `json:"closed_cases"`
	NextAction           string   `json:"next_action"`
	Limitations          []string `json:"limitations"`
}

type CaseCompareOutcome struct {
	Summary         string                   `json:"summary"`
	TotalCases      int                      `json:"total_cases"`
	AfterOpen       int                      `json:"after_open"`
	AfterClosed     int                      `json:"after_closed"`
	AfterAbsent     int                      `json:"after_absent"`
	MaterialChanges int                      `json:"material_changes"`
	ActionCases     []CaseCompareOutcomeCase `json:"action_cases"`
	ClosedCases     []CaseCompareOutcomeCase `json:"closed_cases"`
	AbsentCases     []CaseCompareOutcomeCase `json:"absent_cases"`
	NextAction      string                   `json:"next_action"`
}

type CaseCompareOutcomeCase struct {
	ID                string `json:"id"`
	Title             string `json:"title"`
	Severity          string `json:"severity"`
	Disposition       string `json:"disposition"`
	BeforeState       string `json:"before_state"`
	AfterState        string `json:"after_state"`
	StateReason       string `json:"state_reason"`
	NextStep          string `json:"next_step"`
	AfterEvidenceRefs int    `json:"after_evidence_refs"`
	AfterProofPatches int    `json:"after_proof_patches"`
}

type CaseCompareResult struct {
	ID                    string              `json:"id"`
	Title                 string              `json:"title"`
	Severity              string              `json:"severity"`
	Disposition           string              `json:"disposition"`
	BeforeState           string              `json:"before_state"`
	AfterState            string              `json:"after_state"`
	BeforeStateReason     string              `json:"before_state_reason"`
	AfterStateReason      string              `json:"after_state_reason"`
	BeforeControls        []string            `json:"before_controls"`
	AfterControls         []string            `json:"after_controls"`
	AddedControls         []string            `json:"added_controls"`
	RemovedControls       []string            `json:"removed_controls"`
	BeforeProofPatches    int                 `json:"before_proof_patches"`
	AfterProofPatches     int                 `json:"after_proof_patches"`
	BeforeEvidenceRefs    int                 `json:"before_evidence_refs"`
	AfterEvidenceRefs     int                 `json:"after_evidence_refs"`
	BeforeEvidence        []EvidenceReference `json:"before_evidence_details"`
	AfterEvidence         []EvidenceReference `json:"after_evidence_details"`
	AddedEvidence         []EvidenceReference `json:"added_evidence_refs"`
	RemovedEvidence       []EvidenceReference `json:"removed_evidence_refs"`
	BeforeTargets         []string            `json:"before_targets"`
	AfterTargets          []string            `json:"after_targets"`
	BeforeFlaws           []string            `json:"before_flaws"`
	AfterFlaws            []string            `json:"after_flaws"`
	BeforeRerunCommands   []string            `json:"before_rerun_commands"`
	AfterRerunCommands    []string            `json:"after_rerun_commands"`
	BeforeCompareCommands []string            `json:"before_compare_commands"`
	AfterCompareCommands  []string            `json:"after_compare_commands"`
	BeforeNextStep        string              `json:"before_next_step"`
	AfterNextStep         string              `json:"after_next_step"`
}

type AssessReport struct {
	SchemaVersion     string                  `json:"schema_version"`
	RunID             string                  `json:"run_id"`
	GeneratedAt       time.Time               `json:"generated_at"`
	RunKind           string                  `json:"run_kind"`
	TargetPath        string                  `json:"target_path,omitempty"`
	TargetsFile       string                  `json:"targets_file,omitempty"`
	Targets           []ScanTarget            `json:"targets,omitempty"`
	Mode              string                  `json:"mode"`
	Agent             string                  `json:"agent"`
	StatusFilter      string                  `json:"status_filter"`
	CaseFilter        string                  `json:"case_filter,omitempty"`
	ControlFilter     string                  `json:"control_filter,omitempty"`
	Summary           AssessSummary           `json:"summary"`
	Decision          AssessDecision          `json:"decision"`
	Triage            AssessTriage            `json:"triage"`
	SignalNoise       AssessSignalNoise       `json:"signal_noise"`
	SignalQuality     AssessSignalQuality     `json:"signal_quality"`
	ControlState      AssessControlState      `json:"control_state"`
	Inventory         AssessInventory         `json:"inventory"`
	Exposure          AssessExposure          `json:"exposure"`
	LethalTrifecta    AssessLethalTrifecta    `json:"lethal_trifecta"`
	ClosureEvidence   AssessClosureEvidence   `json:"closure_evidence"`
	Architecture      *ArchitectureReport     `json:"architecture,omitempty"`
	ArchitectureScan  *ArchitectureScanReport `json:"architecture_scan,omitempty"`
	CaseBoard         ControlCatalogReport    `json:"case_board"`
	TopCases          []ControlOperatorCase   `json:"top_cases"`
	TopCaseProofPlan  *ProofPlanReport        `json:"top_case_proof_plan,omitempty"`
	FirstAction       AssessFirstAction       `json:"first_action"`
	OperatorPacket    AssessOperatorPacket    `json:"operator_packet"`
	OperatorWorkbench AssessOperatorWorkbench `json:"operator_workbench"`
	CaseLifecycle     AssessCaseLifecycle     `json:"case_lifecycle"`
	ClosurePlan       []AssessClosurePlanItem `json:"closure_plan"`
	NextCommands      []string                `json:"next_commands"`
	Redaction         RedactionInfo           `json:"redaction"`
	Warnings          []string                `json:"warnings,omitempty"`
	Limitations       []string                `json:"limitations"`
}

type AssessOperatorPacketReport struct {
	SchemaVersion string               `json:"schema_version"`
	RunID         string               `json:"run_id"`
	GeneratedAt   time.Time            `json:"generated_at"`
	RunKind       string               `json:"run_kind"`
	SourceRunKind string               `json:"source_run_kind"`
	TargetPath    string               `json:"target_path,omitempty"`
	TargetsFile   string               `json:"targets_file,omitempty"`
	Targets       []ScanTarget         `json:"targets,omitempty"`
	Mode          string               `json:"mode"`
	Agent         string               `json:"agent"`
	StatusFilter  string               `json:"status_filter"`
	CaseFilter    string               `json:"case_filter,omitempty"`
	ControlFilter string               `json:"control_filter,omitempty"`
	Packet        AssessOperatorPacket `json:"operator_packet"`
	Redaction     RedactionInfo        `json:"redaction"`
	Warnings      []string             `json:"warnings,omitempty"`
	Limitations   []string             `json:"limitations"`
}

type AssessDecision struct {
	Status                    string              `json:"status"`
	Headline                  string              `json:"headline"`
	StartHere                 string              `json:"start_here"`
	TopCaseID                 string              `json:"top_case_id,omitempty"`
	TopCaseTitle              string              `json:"top_case_title,omitempty"`
	CaseSeverity              string              `json:"case_severity,omitempty"`
	CaseState                 string              `json:"case_state,omitempty"`
	CurrentControl            string              `json:"current_control,omitempty"`
	CurrentProofSurface       string              `json:"current_proof_surface,omitempty"`
	WhyPrioritized            string              `json:"why_prioritized,omitempty"`
	InspectionSummary         []string            `json:"inspection_summary"`
	RiskReasons               []string            `json:"risk_reasons"`
	NormalCapabilities        []string            `json:"normal_capabilities"`
	EvidenceSources           []string            `json:"evidence_sources"`
	EvidenceReferences        []EvidenceReference `json:"evidence_refs"`
	PathSummary               []string            `json:"path_summary"`
	MissingHardBarriers       []string            `json:"missing_hard_barriers"`
	PresentHardBarriers       []string            `json:"present_hard_barriers"`
	PartialOrFrictionControls []string            `json:"partial_or_friction_controls"`
	UnknownEvidence           []string            `json:"unknown_evidence"`
	EvidenceGapActions        []string            `json:"evidence_gap_actions"`
	Instruction               string              `json:"instruction,omitempty"`
	ProofSurface              string              `json:"proof_surface,omitempty"`
	ProofCommand              string              `json:"proof_command,omitempty"`
	BeforeProofCommand        string              `json:"before_proof_command,omitempty"`
	GeneratedProofPath        string              `json:"generated_proof_path,omitempty"`
	GeneratedProofPaths       []string            `json:"generated_proof_paths"`
	SuggestedDestination      string              `json:"suggested_destination,omitempty"`
	SuggestedDestinations     []string            `json:"suggested_destinations"`
	DestinationPath           string              `json:"destination_path,omitempty"`
	DestinationPaths          []string            `json:"destination_paths"`
	ApplyCommand              string              `json:"apply_command,omitempty"`
	ApplyCommands             []string            `json:"apply_commands"`
	RerunCommand              string              `json:"rerun_command,omitempty"`
	AfterProofCommand         string              `json:"after_proof_command,omitempty"`
	CompareCommand            string              `json:"compare_command,omitempty"`
	DoneCriteria              []string            `json:"done_criteria"`
	Limitations               []string            `json:"limitations"`
}

type AssessControlState struct {
	Available                 bool     `json:"available"`
	Scope                     string   `json:"scope,omitempty"`
	CaseID                    string   `json:"case_id,omitempty"`
	CaseTitle                 string   `json:"case_title,omitempty"`
	CurrentControl            string   `json:"current_control,omitempty"`
	CurrentProofSurface       string   `json:"current_proof_surface,omitempty"`
	MissingHardBarriers       []string `json:"missing_hard_barriers"`
	PresentHardBarriers       []string `json:"present_hard_barriers"`
	PartialOrFrictionControls []string `json:"partial_or_friction_controls"`
	UnknownEvidence           []string `json:"unknown_evidence"`
	ProofSurfaces             []string `json:"proof_surfaces"`
	EvidenceSources           []string `json:"evidence_sources"`
	PathSummary               []string `json:"path_summary"`
	GraphEdges                []string `json:"graph_edges"`
	Summary                   []string `json:"summary"`
	Limitations               []string `json:"limitations"`
}

type AssessFirstAction struct {
	Available             bool                     `json:"available"`
	CaseID                string                   `json:"case_id,omitempty"`
	Title                 string                   `json:"title,omitempty"`
	Severity              string                   `json:"severity,omitempty"`
	State                 string                   `json:"state,omitempty"`
	WhyFirst              string                   `json:"why_first,omitempty"`
	NextStep              string                   `json:"next_step,omitempty"`
	Targets               []string                 `json:"targets"`
	Flaws                 []string                 `json:"flaws"`
	EvidenceReferences    []EvidenceReference      `json:"evidence_refs"`
	StartingControls      []string                 `json:"starting_controls"`
	ProofSurfaces         []string                 `json:"proof_surfaces"`
	EvidenceExamples      []ControlEvidenceExample `json:"evidence_examples"`
	ProofPatches          []ControlProofPatch      `json:"proof_patches"`
	RerunCommands         []string                 `json:"rerun_commands"`
	CompareCommands       []string                 `json:"compare_commands"`
	PatchExportCommand    string                   `json:"patch_export_command"`
	GeneratedProofPaths   []string                 `json:"generated_proof_paths"`
	SuggestedDestinations []string                 `json:"suggested_destinations"`
	DestinationPaths      []string                 `json:"destination_paths"`
	ApplyCommands         []string                 `json:"apply_commands"`
	SuccessCriteria       []string                 `json:"success_criteria"`
	Workflow              []AssessWorkflowStep     `json:"workflow"`
	CurrentAction         AssessCurrentAction      `json:"current_action"`
}

type AssessCurrentAction struct {
	Available            bool                    `json:"available"`
	WorkflowStepID       string                  `json:"workflow_step_id"`
	WorkflowStepTitle    string                  `json:"workflow_step_title"`
	Instruction          string                  `json:"instruction"`
	Control              string                  `json:"control"`
	Surface              string                  `json:"surface"`
	EvidenceReferences   []EvidenceReference     `json:"evidence_refs"`
	ProofPatchIndex      int                     `json:"proof_patch_index"`
	ProofPatch           *ControlProofPatch      `json:"proof_patch,omitempty"`
	EvidenceExampleIndex int                     `json:"evidence_example_index"`
	EvidenceExample      *ControlEvidenceExample `json:"evidence_example,omitempty"`
	RerunCommand         string                  `json:"rerun_command"`
	CompareCommand       string                  `json:"compare_command"`
	PatchExportCommand   string                  `json:"patch_export_command"`
	GeneratedProofPath   string                  `json:"generated_proof_path,omitempty"`
	SuggestedDestination string                  `json:"suggested_destination,omitempty"`
	DestinationPath      string                  `json:"destination_path,omitempty"`
	ApplyCommand         string                  `json:"apply_command,omitempty"`
	SuccessCriteria      []string                `json:"success_criteria"`
}

type AssessOperatorWorkbench struct {
	Available      bool                        `json:"available"`
	Mode           string                      `json:"mode,omitempty"`
	Case           AssessWorkbenchCase         `json:"case"`
	SignalChain    []AssessSignalNoiseItem     `json:"signal_chain"`
	EvidenceToOpen []EvidenceReference         `json:"evidence_to_open"`
	GraphPath      []string                    `json:"graph_path"`
	Proof          AssessWorkbenchProof        `json:"proof"`
	ProofState     AssessWorkbenchProofState   `json:"proof_state"`
	Verify         AssessWorkbenchVerification `json:"verify"`
	Actions        []AssessWorkbenchAction     `json:"actions"`
	DoneCriteria   []string                    `json:"done_criteria"`
	ChangeReadout  []string                    `json:"change_readout"`
	Limitations    []string                    `json:"limitations"`
}

type AssessWorkbenchCase struct {
	ID          string `json:"id,omitempty"`
	Title       string `json:"title,omitempty"`
	Severity    string `json:"severity,omitempty"`
	State       string `json:"state,omitempty"`
	WhyFirst    string `json:"why_first,omitempty"`
	NextStep    string `json:"next_step,omitempty"`
	CurrentStep string `json:"current_step,omitempty"`
}

type AssessWorkbenchProof struct {
	Mode                  string                  `json:"mode,omitempty"`
	Control               string                  `json:"control,omitempty"`
	Controls              []string                `json:"controls"`
	Surface               string                  `json:"surface,omitempty"`
	Surfaces              []string                `json:"surfaces"`
	Instruction           string                  `json:"instruction,omitempty"`
	ProofPatch            *ControlProofPatch      `json:"proof_patch,omitempty"`
	EvidenceExample       *ControlEvidenceExample `json:"evidence_example,omitempty"`
	GeneratedProofPath    string                  `json:"generated_proof_path,omitempty"`
	GeneratedProofPaths   []string                `json:"generated_proof_paths"`
	SuggestedDestination  string                  `json:"suggested_destination,omitempty"`
	SuggestedDestinations []string                `json:"suggested_destinations"`
	DestinationPath       string                  `json:"destination_path,omitempty"`
	DestinationPaths      []string                `json:"destination_paths"`
	ApplyCommand          string                  `json:"apply_command,omitempty"`
	ApplyCommands         []string                `json:"apply_commands"`
}

type AssessOperatorPacket struct {
	Available       bool                      `json:"available"`
	Status          string                    `json:"status,omitempty"`
	Headline        string                    `json:"headline,omitempty"`
	CaseID          string                    `json:"case_id,omitempty"`
	CaseTitle       string                    `json:"case_title,omitempty"`
	Severity        string                    `json:"severity,omitempty"`
	State           string                    `json:"state,omitempty"`
	CurrentStep     string                    `json:"current_step,omitempty"`
	CurrentControl  string                    `json:"current_control,omitempty"`
	ProofSurface    string                    `json:"proof_surface,omitempty"`
	WhyActionable   []string                  `json:"why_actionable"`
	NormalContext   []string                  `json:"normal_context"`
	EvidenceToOpen  []EvidenceReference       `json:"evidence_to_open"`
	EvidenceSources []string                  `json:"evidence_sources"`
	GraphPath       []string                  `json:"graph_path"`
	MissingControls []string                  `json:"missing_controls"`
	PresentControls []string                  `json:"present_controls"`
	TargetControls  []string                  `json:"target_controls"`
	ProofState      AssessWorkbenchProofState `json:"proof_state"`
	Commands        []AssessOperatorCommand   `json:"commands"`
	DoneCriteria    []string                  `json:"done_criteria"`
	DecisionRules   []string                  `json:"decision_rules"`
	Limitations     []string                  `json:"limitations"`
}

type AssessOperatorCommand struct {
	Step    int      `json:"step"`
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Command string   `json:"command,omitempty"`
	Files   []string `json:"files"`
}

type AssessWorkbenchProofState struct {
	CurrentState           string   `json:"current_state,omitempty"`
	CurrentControl         string   `json:"current_control,omitempty"`
	CurrentMissingControls []string `json:"current_missing_controls"`
	CurrentPresentControls []string `json:"current_present_controls"`
	TargetControls         []string `json:"target_controls"`
	BaselineArtifact       string   `json:"baseline_artifact,omitempty"`
	AfterArtifact          string   `json:"after_artifact,omitempty"`
	CompareArtifact        string   `json:"compare_artifact,omitempty"`
	BaselineCommand        string   `json:"baseline_command,omitempty"`
	AfterCommand           string   `json:"after_command,omitempty"`
	CompareCommand         string   `json:"compare_command,omitempty"`
	ClosureCondition       string   `json:"closure_condition,omitempty"`
	SuccessCriteria        []string `json:"success_criteria"`
	Limitations            []string `json:"limitations"`
}

type AssessWorkbenchVerification struct {
	Commands []string `json:"commands"`
}

type AssessWorkbenchAction struct {
	Step               int                 `json:"step"`
	ID                 string              `json:"id"`
	Title              string              `json:"title"`
	Status             string              `json:"status"`
	Instruction        string              `json:"instruction"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	Files              []string            `json:"files"`
	Commands           []string            `json:"commands"`
	Controls           []string            `json:"controls"`
	DoneCriteria       []string            `json:"done_criteria"`
	Limitations        []string            `json:"limitations"`
}

type AssessCaseLifecycle struct {
	Available     bool                      `json:"available"`
	CaseID        string                    `json:"case_id,omitempty"`
	CaseTitle     string                    `json:"case_title,omitempty"`
	CaseState     string                    `json:"case_state,omitempty"`
	CurrentStepID string                    `json:"current_step_id,omitempty"`
	Summary       string                    `json:"summary"`
	Steps         []AssessCaseLifecycleStep `json:"steps"`
	Readout       []string                  `json:"readout"`
	Limitations   []string                  `json:"limitations"`
}

type AssessCaseLifecycleStep struct {
	ID                 string              `json:"id"`
	Title              string              `json:"title"`
	Status             string              `json:"status"`
	Summary            string              `json:"summary"`
	Commands           []string            `json:"commands"`
	Artifacts          []string            `json:"artifacts"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	ProofSurfaces      []string            `json:"proof_surfaces"`
	Controls           []string            `json:"controls"`
	SuccessCriteria    []string            `json:"success_criteria"`
	Limitations        []string            `json:"limitations"`
}

type AssessClosurePlanItem struct {
	Rank               int                 `json:"rank"`
	Control            string              `json:"control"`
	CaseID             string              `json:"case_id"`
	CaseTitle          string              `json:"case_title"`
	Severity           string              `json:"severity"`
	State              string              `json:"state"`
	WhyThisControl     string              `json:"why_this_control"`
	WhatItCloses       string              `json:"what_it_closes"`
	AffectedFlaws      int                 `json:"affected_flaws"`
	AffectedTargets    int                 `json:"affected_targets"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	ProofSurface       string              `json:"proof_surface"`
	ProofPatch         *ControlProofPatch  `json:"proof_patch,omitempty"`
	RerunCommand       string              `json:"rerun_command"`
	CompareCommand     string              `json:"compare_command"`
	DoneCriteria       []string            `json:"done_criteria"`
	Limitations        []string            `json:"limitations"`
}

type AssessWorkflowStep struct {
	ID                 string              `json:"id"`
	Title              string              `json:"title"`
	Summary            string              `json:"summary"`
	Current            bool                `json:"current"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	StartingControls   []string            `json:"starting_controls"`
	ProofSurfaces      []string            `json:"proof_surfaces"`
	Commands           []string            `json:"commands"`
	SuccessCriteria    []string            `json:"success_criteria"`
}

type AssessSummary struct {
	Targets                      int    `json:"targets"`
	CompletedTargets             int    `json:"completed_targets"`
	Errors                       int    `json:"errors"`
	Surfaces                     int    `json:"surfaces"`
	Facts                        int    `json:"facts"`
	GraphNodes                   int    `json:"graph_nodes"`
	GraphEdges                   int    `json:"graph_edges"`
	ExposurePaths                int    `json:"exposure_paths"`
	Exposed                      int    `json:"exposed"`
	Protected                    int    `json:"protected"`
	Inconclusive                 int    `json:"inconclusive"`
	ArchitectureFlaws            int    `json:"architecture_flaws"`
	BreakingArchitectureFlaws    int    `json:"breaking_architecture_flaws"`
	ControlledArchitectureFlaws  int    `json:"controlled_architecture_flaws"`
	UnknownArchitectureFlaws     int    `json:"unknown_architecture_flaws"`
	NotObservedArchitectureFlaws int    `json:"not_observed_architecture_flaws"`
	OperatorCases                int    `json:"operator_cases"`
	MissingHardBarrierControls   int    `json:"missing_hard_barrier_controls"`
	CriticalMissingHardBarriers  int    `json:"critical_missing_hard_barriers"`
	HighMissingHardBarriers      int    `json:"high_missing_hard_barriers"`
	MediumMissingHardBarriers    int    `json:"medium_missing_hard_barriers"`
	LowMissingHardBarriers       int    `json:"low_missing_hard_barriers"`
	TopCaseID                    string `json:"top_case_id,omitempty"`
	TopCaseTitle                 string `json:"top_case_title,omitempty"`
	TopCaseNextStep              string `json:"top_case_next_step,omitempty"`
}

type AssessTriage struct {
	Status                    string              `json:"status"`
	Headline                  string              `json:"headline"`
	StartHere                 string              `json:"start_here"`
	HardRiskSignals           []string            `json:"hard_risk_signals"`
	NormalCapabilities        []string            `json:"normal_capabilities"`
	MissingHardBarriers       []string            `json:"missing_hard_barriers"`
	PartialOrFrictionControls []string            `json:"partial_or_friction_controls"`
	PresentHardBarriers       []string            `json:"present_hard_barriers"`
	UnknownEvidence           []string            `json:"unknown_evidence"`
	EvidenceGapActions        []string            `json:"evidence_gap_actions"`
	SignalDetails             []AssessSignal      `json:"signal_details"`
	EvidenceReferences        []EvidenceReference `json:"evidence_refs"`
	NextAction                string              `json:"next_action"`
	ProofLoop                 []string            `json:"proof_loop"`
}

type AssessSignal struct {
	ID                 string              `json:"id"`
	Category           string              `json:"category"`
	Disposition        string              `json:"disposition"`
	Summary            string              `json:"summary"`
	WhyItMatters       string              `json:"why_it_matters"`
	RiskBoundary       string              `json:"risk_boundary"`
	GraphEdges         []string            `json:"graph_edges"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	RelatedControls    []string            `json:"related_controls"`
	Limitations        []string            `json:"limitations"`
}

type AssessSignalQuality struct {
	Status               string              `json:"status"`
	Summary              string              `json:"summary"`
	ActionableBecause    []string            `json:"actionable_because"`
	ExpectedCapabilities []string            `json:"expected_capabilities"`
	NoiseFilters         []string            `json:"noise_filters"`
	ControlBreakpoints   []string            `json:"control_breakpoints"`
	EvidenceGaps         []string            `json:"evidence_gaps"`
	GraphEdges           []string            `json:"graph_edges"`
	EvidenceReferences   []EvidenceReference `json:"evidence_refs"`
	DecisionRules        []string            `json:"decision_rules"`
	Limitations          []string            `json:"limitations"`
}

type AssessSignalNoise struct {
	Status             string                  `json:"status"`
	Summary            string                  `json:"summary"`
	ExpectedCapability []AssessSignalNoiseItem `json:"expected_capability"`
	ExposureTransition []AssessSignalNoiseItem `json:"exposure_transition"`
	ControlEvidence    []AssessSignalNoiseItem `json:"control_evidence"`
	DowngradeEvidence  []AssessSignalNoiseItem `json:"downgrade_evidence"`
	EvidenceGaps       []AssessSignalNoiseItem `json:"evidence_gaps"`
	DecisionRules      []string                `json:"decision_rules"`
	Limitations        []string                `json:"limitations"`
}

type AssessSignalNoiseItem struct {
	ID                 string              `json:"id"`
	Category           string              `json:"category"`
	Disposition        string              `json:"disposition"`
	Summary            string              `json:"summary"`
	RiskBoundary       string              `json:"risk_boundary,omitempty"`
	GraphEdges         []string            `json:"graph_edges"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	Sources            []string            `json:"sources"`
	Controls           []string            `json:"controls"`
	Limitations        []string            `json:"limitations"`
}

type AssessInventory struct {
	TargetPath        string        `json:"target_path,omitempty"`
	Surfaces          int           `json:"surfaces"`
	Facts             int           `json:"facts"`
	GraphNodes        int           `json:"graph_nodes"`
	GraphEdges        int           `json:"graph_edges"`
	Runtimes          int           `json:"runtimes"`
	TrustInputs       int           `json:"trust_inputs"`
	Tools             int           `json:"tools"`
	Authorities       int           `json:"authorities"`
	Controls          int           `json:"controls"`
	Boundaries        int           `json:"boundaries"`
	SurfaceCategories []AssessCount `json:"surface_categories"`
	HandlingModes     []AssessCount `json:"handling_modes"`
	SurfaceMap        []SurfaceMap  `json:"surface_map"`
	FactHighlights    []AssessFact  `json:"fact_highlights"`
	Limitations       []string      `json:"limitations,omitempty"`
}

type AssessFact struct {
	ID            string   `json:"id,omitempty"`
	Type          string   `json:"type"`
	Runtime       string   `json:"runtime,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	Target        string   `json:"target,omitempty"`
	Source        string   `json:"source,omitempty"`
	EvidenceGrade string   `json:"evidence_grade"`
	Redaction     string   `json:"redaction"`
	Summary       string   `json:"summary"`
	Limitations   []string `json:"limitations,omitempty"`
}

type AssessExposure struct {
	Paths        int              `json:"paths"`
	Exposed      int              `json:"exposed"`
	Protected    int              `json:"protected"`
	Inconclusive int              `json:"inconclusive"`
	TopPaths     []ExposureResult `json:"top_paths"`
}

type AssessLethalTrifecta struct {
	Status             Status               `json:"status"`
	Present            bool                 `json:"present"`
	Protected          bool                 `json:"protected"`
	Complete           bool                 `json:"complete"`
	ProofMode          ProofMode            `json:"proof_mode"`
	Summary            string               `json:"summary"`
	Ingredients        []TrifectaIngredient `json:"ingredients"`
	GraphEdges         []string             `json:"graph_edges"`
	EvidenceReferences []EvidenceReference  `json:"evidence_refs"`
	ControlsBreakPath  []string             `json:"controls_break_path"`
	DecisionRules      []string             `json:"decision_rules"`
	Limitations        []string             `json:"limitations"`
}

type TrifectaIngredient struct {
	ID                 string              `json:"id"`
	Label              string              `json:"label"`
	Present            bool                `json:"present"`
	Summary            string              `json:"summary"`
	GraphEdges         []string            `json:"graph_edges"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
}

type AssessClosureEvidence struct {
	ProtectedExposurePaths       int                 `json:"protected_exposure_paths"`
	ControlledArchitectureFlaws  int                 `json:"controlled_architecture_flaws"`
	PartialArchitectureFlaws     int                 `json:"partial_architecture_flaws"`
	HardBarriersObserved         []string            `json:"hard_barriers_observed"`
	PartialOrFrictionControls    []string            `json:"partial_or_friction_controls"`
	RemainingMissingHardBarriers []string            `json:"remaining_missing_hard_barriers"`
	ControlledPaths              []AssessClosurePath `json:"controlled_paths"`
	PartialPaths                 []AssessClosurePath `json:"partial_paths"`
}

type AssessClosurePath struct {
	Target                       string              `json:"target,omitempty"`
	ID                           string              `json:"id"`
	Title                        string              `json:"title"`
	Status                       ZeroTrustStatus     `json:"status"`
	ControlTestResult            string              `json:"control_test_result"`
	Controls                     []string            `json:"controls"`
	HardBarriersObserved         []string            `json:"hard_barriers_observed"`
	PartialOrFrictionControls    []string            `json:"partial_or_friction_controls"`
	RemainingMissingHardBarriers []string            `json:"remaining_missing_hard_barriers"`
	GraphEdges                   []string            `json:"graph_edges"`
	EvidenceReferences           []EvidenceReference `json:"evidence_refs"`
}

type AssessCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type SurfaceMap struct {
	Runtime            string        `json:"runtime"`
	Scope              string        `json:"scope"`
	SurfaceCount       int           `json:"surface_count"`
	Parsed             int           `json:"parsed"`
	Summarized         int           `json:"summarized"`
	BoundaryIndicators int           `json:"boundary_indicators"`
	Skipped            int           `json:"skipped"`
	SourceRefs         []string      `json:"source_refs"`
	Categories         []AssessCount `json:"categories"`
	HandlingModes      []AssessCount `json:"handling_modes"`
	Authorities        []string      `json:"authorities"`
	Tools              []string      `json:"tools"`
	Controls           []string      `json:"controls"`
	Limitations        []string      `json:"limitations,omitempty"`
}

type ControlCatalogSummary struct {
	Controls int `json:"controls"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Targets  int `json:"targets"`
	Flaws    int `json:"flaws"`
}

type ControlOperatorCase struct {
	ID                 string                   `json:"id"`
	Title              string                   `json:"title"`
	Severity           string                   `json:"severity"`
	Rank               int                      `json:"rank"`
	PriorityReason     string                   `json:"priority_reason"`
	State              string                   `json:"state"`
	StateReason        string                   `json:"state_reason"`
	Question           string                   `json:"question"`
	Finding            string                   `json:"finding"`
	NextStep           string                   `json:"next_step"`
	TargetCount        int                      `json:"target_count"`
	FlawCount          int                      `json:"flaw_count"`
	ControlCount       int                      `json:"control_count"`
	Targets            []string                 `json:"targets"`
	Flaws              []string                 `json:"flaws"`
	EvidenceReferences []EvidenceReference      `json:"evidence_refs"`
	StartingControls   []string                 `json:"starting_controls"`
	StartingTaskIDs    []string                 `json:"starting_task_ids"`
	ProofSurfaces      []string                 `json:"proof_surfaces"`
	EvidenceExamples   []ControlEvidenceExample `json:"evidence_examples"`
	ProofPatches       []ControlProofPatch      `json:"proof_patches"`
	PatchExportCommand string                   `json:"patch_export_command,omitempty"`
	RerunCommands      []string                 `json:"rerun_commands"`
	CompareCommands    []string                 `json:"compare_commands"`
	SuccessCriteria    []string                 `json:"success_criteria"`
	Limitations        []string                 `json:"limitations"`
}

type ControlBreakPathWorkstream struct {
	ID                 string              `json:"id"`
	Title              string              `json:"title"`
	Severity           string              `json:"severity"`
	ControlCount       int                 `json:"control_count"`
	FlawCount          int                 `json:"flaw_count"`
	TargetCount        int                 `json:"target_count"`
	Controls           []string            `json:"controls"`
	Flaws              []string            `json:"flaws"`
	Targets            []string            `json:"targets"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	ProofSurfaces      []string            `json:"proof_surfaces"`
	StartingTaskIDs    []string            `json:"starting_task_ids"`
	StartingControls   []string            `json:"starting_controls"`
	Rationale          string              `json:"rationale"`
	SuccessCriteria    []string            `json:"success_criteria"`
	Limitations        []string            `json:"limitations"`
}

type ControlProofSpec struct {
	Control              string   `json:"control"`
	EvidenceKind         string   `json:"evidence_kind"`
	ProofSurfaces        []string `json:"proof_surfaces"`
	RecognizedIndicators []string `json:"recognized_indicators"`
	Notes                []string `json:"notes"`
	Limitations          []string `json:"limitations"`
}

type ControlVerificationTask struct {
	ID                   string                   `json:"id"`
	Control              string                   `json:"control"`
	Severity             string                   `json:"severity"`
	Targets              []string                 `json:"targets"`
	Question             string                   `json:"question"`
	Why                  string                   `json:"why"`
	EvidenceReferences   []EvidenceReference      `json:"evidence_refs"`
	ProofSurfaces        []string                 `json:"proof_surfaces"`
	RecognizedIndicators []string                 `json:"recognized_indicators"`
	EvidenceExamples     []ControlEvidenceExample `json:"evidence_examples"`
	ProofPatches         []ControlProofPatch      `json:"proof_patches"`
	Actions              []string                 `json:"actions"`
	RerunCommands        []string                 `json:"rerun_commands"`
	SuccessCriteria      []string                 `json:"success_criteria"`
	Limitations          []string                 `json:"limitations"`
}

type ControlEvidenceExample struct {
	Surface     string   `json:"surface"`
	Summary     string   `json:"summary"`
	Example     string   `json:"example"`
	Limitations []string `json:"limitations"`
}

type ControlProofPatch struct {
	Control         string                   `json:"control"`
	Surface         string                   `json:"surface"`
	Format          string                   `json:"format"`
	Operation       string                   `json:"operation"`
	Summary         string                   `json:"summary"`
	Fields          []ControlProofPatchField `json:"fields"`
	Example         string                   `json:"example"`
	RerunCommands   []string                 `json:"rerun_commands"`
	SuccessCriteria []string                 `json:"success_criteria"`
	Limitations     []string                 `json:"limitations"`
}

type ControlProofPatchField struct {
	Indicator string `json:"indicator"`
	Name      string `json:"name"`
	ValueJSON string `json:"value_json"`
}

type ArchitectureTargetReport struct {
	Target  ScanTarget              `json:"target"`
	Summary ZeroTrustSummary        `json:"summary"`
	Flaws   []ZeroTrustArchitecture `json:"flaws"`
	Error   string                  `json:"error,omitempty"`
}

type ArchitectureFlawGroup struct {
	ID                    string           `json:"id"`
	Title                 string           `json:"title"`
	Severity              string           `json:"severity"`
	Principle             string           `json:"principle"`
	Tier                  string           `json:"tier"`
	StatusCounts          ZeroTrustSummary `json:"status_counts"`
	TargetCount           int              `json:"target_count"`
	Targets               []string         `json:"targets"`
	ControlTestResults    map[string]int   `json:"control_test_results"`
	ControlEvidenceNeeded []string         `json:"control_evidence_needed"`
	EvidenceSurfaces      []string         `json:"evidence_surfaces"`
	EvidenceSources       []string         `json:"evidence_sources"`
	Actions               []string         `json:"actions"`
}

type ArchitectureControlTest struct {
	Question                  string   `json:"question"`
	Result                    string   `json:"result"`
	Summary                   string   `json:"summary"`
	HardBarriersObserved      []string `json:"hard_barriers_observed"`
	PartialOrFrictionControls []string `json:"partial_or_friction_controls"`
	MissingHardBarriers       []string `json:"missing_hard_barriers"`
}

type ArchitectureClosure struct {
	Control            string              `json:"control"`
	ControlTestResult  string              `json:"control_test_result"`
	Severity           string              `json:"severity"`
	FlawCount          int                 `json:"flaw_count"`
	TargetCount        int                 `json:"target_count"`
	Flaws              []string            `json:"flaws"`
	CheckIDs           []string            `json:"check_ids"`
	Targets            []string            `json:"targets"`
	EvidenceSources    []string            `json:"evidence_sources"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	EvidenceSurfaces   []string            `json:"evidence_surfaces"`
	Actions            []string            `json:"actions"`
}

type ArchitectureClosureFamily struct {
	ID                 string              `json:"id"`
	Title              string              `json:"title"`
	Severity           string              `json:"severity"`
	ControlCount       int                 `json:"control_count"`
	FlawCount          int                 `json:"flaw_count"`
	TargetCount        int                 `json:"target_count"`
	Controls           []string            `json:"controls"`
	Flaws              []string            `json:"flaws"`
	CheckIDs           []string            `json:"check_ids"`
	Targets            []string            `json:"targets"`
	EvidenceSources    []string            `json:"evidence_sources"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	EvidenceSurfaces   []string            `json:"evidence_surfaces"`
	Actions            []string            `json:"actions"`
}

type EvidenceReference struct {
	Target    string `json:"target,omitempty"`
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Source    string `json:"source,omitempty"`
	LineStart int    `json:"line_start,omitempty"`
	LineEnd   int    `json:"line_end,omitempty"`
	Summary   string `json:"summary"`
}

type ArchitectureEvidencePlan struct {
	NextCollector   string           `json:"next_collector"`
	GapCount        int              `json:"gap_count"`
	TargetCount     int              `json:"target_count"`
	StatusCounts    ZeroTrustSummary `json:"status_counts"`
	Boundaries      []string         `json:"boundaries"`
	CheckIDs        []string         `json:"check_ids"`
	Targets         []string         `json:"targets"`
	MissingEvidence []string         `json:"missing_evidence"`
	WhyItMatters    []string         `json:"why_it_matters"`
}

type ArchitectureFrameworkArea struct {
	ID                    string           `json:"id"`
	Area                  string           `json:"area"`
	Source                string           `json:"source"`
	Tier                  string           `json:"tier"`
	StatusCounts          ZeroTrustSummary `json:"status_counts"`
	TargetCount           int              `json:"target_count"`
	Targets               []string         `json:"targets"`
	CheckIDs              []string         `json:"check_ids"`
	Flaws                 []string         `json:"flaws"`
	EvidenceSources       []string         `json:"evidence_sources"`
	Controls              []string         `json:"controls"`
	ControlEvidenceNeeded []string         `json:"control_evidence_needed"`
	MissingEvidence       []string         `json:"missing_evidence"`
	NextCollectors        []string         `json:"next_collectors"`
	Limitations           []string         `json:"limitations"`
}

type ArchitectureBoundary struct {
	CheckID               string           `json:"check_id"`
	Boundary              string           `json:"boundary"`
	Principle             string           `json:"principle"`
	Tier                  string           `json:"tier"`
	DesignTest            string           `json:"design_test"`
	StatusCounts          ZeroTrustSummary `json:"status_counts"`
	TargetCount           int              `json:"target_count"`
	BreakingTargets       []string         `json:"breaking_targets"`
	ControlledTargets     []string         `json:"controlled_targets"`
	UnknownTargets        []string         `json:"unknown_targets"`
	NotObservedTargets    []string         `json:"not_observed_targets"`
	EvidenceSources       []string         `json:"evidence_sources"`
	Controls              []string         `json:"controls"`
	ControlEvidenceNeeded []string         `json:"control_evidence_needed"`
	EvidenceSurfaces      []string         `json:"evidence_surfaces"`
	MissingEvidence       []string         `json:"missing_evidence"`
	NextCollectors        []string         `json:"next_collectors"`
	Actions               []string         `json:"actions"`
	Limitations           []string         `json:"limitations"`
}

type StorySummary struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Persona      string `json:"persona"`
	UserQuestion string `json:"user_question"`
	Runtime      string `json:"runtime"`
	Mode         string `json:"mode"`
}

type RedactionInfo struct {
	Level                  string `json:"level"`
	SensitivePathsIncluded bool   `json:"sensitive_paths_included"`
	CanaryValuesIncluded   bool   `json:"canary_values_included"`
}

type ZeroTrustStatus string

const (
	ZeroTrustBreaking    ZeroTrustStatus = "breaking"
	ZeroTrustControlled  ZeroTrustStatus = "controlled"
	ZeroTrustUnknown     ZeroTrustStatus = "unknown"
	ZeroTrustNotObserved ZeroTrustStatus = "not_observed"
)

type ZeroTrust struct {
	FrameworkVersion    string                  `json:"framework_version"`
	Summary             ZeroTrustSummary        `json:"summary"`
	ArchitectureSummary ZeroTrustSummary        `json:"architecture_summary"`
	ArchitectureFlaws   []ZeroTrustArchitecture `json:"architecture_flaws"`
	Coverage            ZeroTrustCoverage       `json:"coverage"`
	Maturity            ZeroTrustMaturity       `json:"maturity"`
	Checks              []ZeroTrustCheck        `json:"checks"`
}

type ZeroTrustSummary struct {
	Total       int `json:"total"`
	Breaking    int `json:"breaking"`
	Controlled  int `json:"controlled"`
	Unknown     int `json:"unknown"`
	NotObserved int `json:"not_observed"`
}

type ZeroTrustCheck struct {
	ID          string              `json:"id"`
	Principle   string              `json:"principle"`
	Boundary    string              `json:"boundary"`
	Tier        string              `json:"tier"`
	Status      ZeroTrustStatus     `json:"status"`
	DesignTest  string              `json:"design_test"`
	Finding     string              `json:"finding"`
	Evidence    []ZeroTrustEvidence `json:"evidence"`
	GraphEdges  []string            `json:"graph_edges"`
	Controls    []string            `json:"controls,omitempty"`
	Actions     []string            `json:"actions"`
	Limitations []string            `json:"limitations,omitempty"`
}

type ZeroTrustArchitecture struct {
	ID                    string                  `json:"id"`
	Title                 string                  `json:"title"`
	Status                ZeroTrustStatus         `json:"status"`
	Severity              string                  `json:"severity"`
	Principle             string                  `json:"principle"`
	Tier                  string                  `json:"tier"`
	Boundaries            []string                `json:"boundaries"`
	CheckIDs              []string                `json:"check_ids"`
	Finding               string                  `json:"finding"`
	WhyItMatters          string                  `json:"why_it_matters"`
	ControlTest           ArchitectureControlTest `json:"control_test"`
	Evidence              []ZeroTrustEvidence     `json:"evidence"`
	GraphEdges            []string                `json:"graph_edges"`
	Controls              []string                `json:"controls,omitempty"`
	ControlEvidenceNeeded []string                `json:"control_evidence_needed"`
	EvidenceSurfaces      []string                `json:"evidence_surfaces"`
	Actions               []string                `json:"actions"`
	Limitations           []string                `json:"limitations,omitempty"`
}

type ZeroTrustEvidence struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Source    string `json:"source,omitempty"`
	LineStart int    `json:"line_start,omitempty"`
	LineEnd   int    `json:"line_end,omitempty"`
	Summary   string `json:"summary"`
}

type ZeroTrustCoverage struct {
	Known       int            `json:"known"`
	Gaps        int            `json:"gaps"`
	Unknown     int            `json:"unknown"`
	NotObserved int            `json:"not_observed"`
	GapDetails  []ZeroTrustGap `json:"gap_details"`
}

type ZeroTrustGap struct {
	CheckID         string          `json:"check_id"`
	Boundary        string          `json:"boundary"`
	Status          ZeroTrustStatus `json:"status"`
	MissingEvidence []string        `json:"missing_evidence"`
	WhyItMatters    string          `json:"why_it_matters"`
	NextCollector   string          `json:"next_collector"`
}

type ZeroTrustMaturity struct {
	TargetTier   string                   `json:"target_tier"`
	Summary      ZeroTrustMaturitySummary `json:"summary"`
	Requirements []ZeroTrustRequirement   `json:"requirements"`
}

type ZeroTrustMaturitySummary struct {
	Total        int `json:"total"`
	Met          int `json:"met"`
	Gaps         int `json:"gaps"`
	Breaking     int `json:"breaking"`
	Unknown      int `json:"unknown"`
	NotObserved  int `json:"not_observed"`
	HardBarriers int `json:"hard_barriers"`
	FrictionOnly int `json:"friction_only"`
}

type ZeroTrustRequirement struct {
	ID              string              `json:"id"`
	Tier            string              `json:"tier"`
	Principle       string              `json:"principle"`
	Capability      string              `json:"capability"`
	Status          ZeroTrustStatus     `json:"status"`
	ControlQuality  string              `json:"control_quality"`
	Finding         string              `json:"finding"`
	Evidence        []ZeroTrustEvidence `json:"evidence"`
	Controls        []string            `json:"controls,omitempty"`
	MissingEvidence []string            `json:"missing_evidence,omitempty"`
	Actions         []string            `json:"actions"`
}

type Evidence struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Grade   string `json:"grade"`
	Source  string `json:"source,omitempty"`
	Runtime string `json:"runtime,omitempty"`
	Summary string `json:"summary"`
}

type Surface struct {
	ID                 string `json:"id"`
	Path               string `json:"-"`
	Runtime            string `json:"runtime"`
	Scope              string `json:"scope"`
	Category           string `json:"category"`
	Kind               string `json:"kind"`
	HandlingMode       string `json:"handling_mode"`
	Source             string `json:"source"`
	Summary            string `json:"summary"`
	ApproxBytes        int64  `json:"approx_bytes,omitempty"`
	FileCount          int    `json:"file_count,omitempty"`
	SensitiveNameCount int    `json:"sensitive_name_count,omitempty"`
}

type Fact struct {
	ID            string   `json:"id"`
	Type          string   `json:"type"`
	Runtime       string   `json:"runtime,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	Source        string   `json:"source,omitempty"`
	HandlingMode  string   `json:"handling_mode,omitempty"`
	EvidenceGrade string   `json:"evidence_grade"`
	Redaction     string   `json:"redaction"`
	Summary       string   `json:"summary"`
	Limitations   []string `json:"limitations,omitempty"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Node struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Label   string `json:"label"`
	Runtime string `json:"runtime,omitempty"`
	Source  string `json:"source,omitempty"`
}

type Edge struct {
	From       string `json:"from"`
	Type       string `json:"type"`
	To         string `json:"to"`
	EvidenceID string `json:"evidence_id,omitempty"`
}

func (e Edge) Key() string {
	return e.From + "|" + e.Type + "|" + e.To
}

func (g Graph) HasNode(id string) bool {
	for _, node := range g.Nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}

func (g Graph) HasEdge(key string) bool {
	for _, edge := range g.Edges {
		if edge.Key() == key {
			return true
		}
	}
	return false
}

type ExposureResult struct {
	ID                 string              `json:"id"`
	Title              string              `json:"title"`
	Status             Status              `json:"status"`
	ProofMode          ProofMode           `json:"proof_mode"`
	Runtimes           []string            `json:"runtimes,omitempty"`
	PathNodes          []string            `json:"path_nodes"`
	PathEdges          []string            `json:"path_edges"`
	EvidenceReferences []EvidenceReference `json:"evidence_refs"`
	Observation        Observation         `json:"observation"`
	ControlsBreakPath  []string            `json:"controls_break_path,omitempty"`
	WhyItMatters       string              `json:"why_it_matters"`
	WhatWasTested      string              `json:"what_was_tested"`
	Limitations        []string            `json:"limitations"`
}

type Observation struct {
	Status  ObservationStatus `json:"status"`
	Summary string            `json:"summary"`
}

type Collection struct {
	Surfaces    []Surface         `json:"surfaces,omitempty"`
	Facts       []Fact            `json:"facts,omitempty"`
	Runtimes    []RuntimeEvidence `json:"runtimes"`
	TrustInputs []TrustInput      `json:"trust_inputs"`
	Tools       []Tool            `json:"tools"`
	Authorities []Authority       `json:"authorities"`
	Controls    []Control         `json:"controls"`
	Boundaries  []Boundary        `json:"boundaries"`
	Evidence    []Evidence        `json:"evidence"`
	Warnings    []string          `json:"warnings,omitempty"`
}

type InventoryReport struct {
	SchemaVersion string        `json:"schema_version"`
	RunID         string        `json:"run_id"`
	GeneratedAt   time.Time     `json:"generated_at"`
	RunKind       string        `json:"run_kind"`
	TargetPath    string        `json:"target_path"`
	Mode          string        `json:"mode"`
	Agent         string        `json:"agent"`
	Collection    Collection    `json:"collection"`
	SurfaceMap    []SurfaceMap  `json:"surface_map"`
	Graph         Graph         `json:"graph"`
	Redaction     RedactionInfo `json:"redaction"`
	Warnings      []string      `json:"warnings,omitempty"`
	Limitations   []string      `json:"limitations"`
}

type ScanTarget struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

type ScanTargetResult struct {
	Target ScanTarget `json:"target"`
	Report Report     `json:"report,omitempty"`
	Error  string     `json:"error,omitempty"`
}

type ScanSummary struct {
	Targets       int `json:"targets"`
	Completed     int `json:"completed"`
	Errors        int `json:"errors"`
	Exposed       int `json:"exposed"`
	Protected     int `json:"protected"`
	Inconclusive  int `json:"inconclusive"`
	ExposurePaths int `json:"exposure_paths"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
}

type ScanReport struct {
	SchemaVersion  string             `json:"schema_version"`
	RunID          string             `json:"run_id"`
	GeneratedAt    time.Time          `json:"generated_at"`
	RunKind        string             `json:"run_kind"`
	TargetsFile    string             `json:"targets_file,omitempty"`
	Mode           string             `json:"mode"`
	Agent          string             `json:"agent"`
	Summary        ScanSummary        `json:"summary"`
	Targets        []ScanTargetResult `json:"targets"`
	Interpretation Interpretation     `json:"interpretation"`
	Redaction      RedactionInfo      `json:"redaction"`
	Warnings       []string           `json:"warnings,omitempty"`
	Limitations    []string           `json:"limitations"`
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Priority string

const (
	PriorityP0 Priority = "p0"
	PriorityP1 Priority = "p1"
	PriorityP2 Priority = "p2"
	PriorityP3 Priority = "p3"
	PriorityP4 Priority = "p4"
)

type Disposition string

const (
	DispositionFixNow     Disposition = "fix_now"
	DispositionReview     Disposition = "review"
	DispositionMonitor    Disposition = "monitor"
	DispositionControlled Disposition = "controlled"
	DispositionExpected   Disposition = "expected_capability"
)

type Interpretation struct {
	Mode           string       `json:"mode"`
	Engine         string       `json:"engine"`
	AvailableModes []string     `json:"available_modes,omitempty"`
	FutureModes    []string     `json:"future_modes,omitempty"`
	Summary        IssueSummary `json:"summary"`
	Issues         []Issue      `json:"issues"`
	Limitations    []string     `json:"limitations"`
	PolicySource   string       `json:"policy_source,omitempty"`
	ReviewSource   string       `json:"review_source,omitempty"`
	RequestDigest  string       `json:"request_digest,omitempty"`
}

type IssueSummary struct {
	Total      int `json:"total"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Info       int `json:"info"`
	FixNow     int `json:"fix_now"`
	Review     int `json:"review"`
	Monitor    int `json:"monitor"`
	Controlled int `json:"controlled"`
	Expected   int `json:"expected"`
}

type Issue struct {
	ID                 string      `json:"id"`
	Title              string      `json:"title"`
	Severity           Severity    `json:"severity"`
	Priority           Priority    `json:"priority"`
	Disposition        Disposition `json:"disposition"`
	Category           string      `json:"category"`
	ExposureID         string      `json:"exposure_id,omitempty"`
	ExposureStatus     Status      `json:"exposure_status,omitempty"`
	RuleID             string      `json:"rule_id"`
	RuleSource         string      `json:"rule_source"`
	InterpretationMode string      `json:"interpretation_mode"`
	AffectedTarget     string      `json:"affected_target,omitempty"`
	Rationale          string      `json:"rationale"`
	Signals            []string    `json:"signals"`
	GraphEdges         []string    `json:"graph_edges"`
	Controls           []string    `json:"controls,omitempty"`
	Actions            []string    `json:"actions"`
	Confidence         string      `json:"confidence"`
}

type RulePolicy struct {
	Version string       `json:"version"`
	Rules   []CustomRule `json:"rules"`
}

type CustomRule struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description,omitempty"`
	Category    string        `json:"category,omitempty"`
	Severity    Severity      `json:"severity"`
	Priority    Priority      `json:"priority"`
	Disposition Disposition   `json:"disposition"`
	When        RuleCondition `json:"when"`
	Rationale   string        `json:"rationale,omitempty"`
	Actions     []string      `json:"actions,omitempty"`
}

type RuleCondition struct {
	Mode                      string         `json:"mode,omitempty"`
	ExposureID                string         `json:"exposure_id,omitempty"`
	ExposureStatus            Status         `json:"exposure_status,omitempty"`
	HasNodes                  []string       `json:"has_nodes,omitempty"`
	HasEdges                  []string       `json:"has_edges,omitempty"`
	HasControls               []string       `json:"has_controls,omitempty"`
	MissingControls           []string       `json:"missing_controls,omitempty"`
	MinSurfaceCountByCategory map[string]int `json:"min_surface_count_by_category,omitempty"`
}

type LLMReviewRequest struct {
	SchemaVersion      string           `json:"schema_version"`
	Target             string           `json:"target"`
	Mode               string           `json:"mode"`
	Question           string           `json:"question"`
	Instructions       []string         `json:"instructions"`
	Collection         Collection       `json:"collection"`
	Graph              Graph            `json:"graph"`
	Exposures          []ExposureResult `json:"exposures"`
	Deterministic      Interpretation   `json:"deterministic_interpretation"`
	Redaction          RedactionInfo    `json:"redaction"`
	Limitations        []string         `json:"limitations"`
	AllowedPriorities  []Priority       `json:"allowed_priorities"`
	AllowedSeverities  []Severity       `json:"allowed_severities"`
	AllowedStatuses    []Status         `json:"allowed_statuses"`
	AllowedDisposition []Disposition    `json:"allowed_dispositions"`
}

type LLMReviewResponse struct {
	SchemaVersion string   `json:"schema_version"`
	Reviewer      string   `json:"reviewer,omitempty"`
	Model         string   `json:"model,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	Issues        []Issue  `json:"issues"`
	Limitations   []string `json:"limitations,omitempty"`
}

type RuntimeEvidence struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	Scope   string `json:"scope"`
	Summary string `json:"summary"`
}

type TrustInput struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Runtime string `json:"runtime,omitempty"`
	Source  string `json:"source"`
	Risky   bool   `json:"risky"`
	Summary string `json:"summary"`
}

type Tool struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Runtime string `json:"runtime"`
	Source  string `json:"source"`
	Risky   bool   `json:"risky"`
	Summary string `json:"summary"`
}

type Authority struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Runtime string `json:"runtime"`
	Source  string `json:"source"`
	Summary string `json:"summary"`
}

type Control struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Runtime string `json:"runtime,omitempty"`
	Source  string `json:"source"`
	Summary string `json:"summary"`
}

type Boundary struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Source   string `json:"source,omitempty"`
	Abstract bool   `json:"abstract"`
	Summary  string `json:"summary"`
}
