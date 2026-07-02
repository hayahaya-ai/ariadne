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

type AssessReport struct {
	SchemaVersion    string                  `json:"schema_version"`
	RunID            string                  `json:"run_id"`
	GeneratedAt      time.Time               `json:"generated_at"`
	RunKind          string                  `json:"run_kind"`
	TargetPath       string                  `json:"target_path,omitempty"`
	Targets          []ScanTarget            `json:"targets,omitempty"`
	Mode             string                  `json:"mode"`
	Agent            string                  `json:"agent"`
	StatusFilter     string                  `json:"status_filter"`
	Summary          AssessSummary           `json:"summary"`
	Inventory        AssessInventory         `json:"inventory"`
	Exposure         AssessExposure          `json:"exposure"`
	ClosureEvidence  AssessClosureEvidence   `json:"closure_evidence"`
	Architecture     *ArchitectureReport     `json:"architecture,omitempty"`
	ArchitectureScan *ArchitectureScanReport `json:"architecture_scan,omitempty"`
	CaseBoard        ControlCatalogReport    `json:"case_board"`
	TopCases         []ControlOperatorCase   `json:"top_cases"`
	NextCommands     []string                `json:"next_commands"`
	Redaction        RedactionInfo           `json:"redaction"`
	Warnings         []string                `json:"warnings,omitempty"`
	Limitations      []string                `json:"limitations"`
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
	Limitations       []string      `json:"limitations,omitempty"`
}

type AssessExposure struct {
	Paths        int              `json:"paths"`
	Exposed      int              `json:"exposed"`
	Protected    int              `json:"protected"`
	Inconclusive int              `json:"inconclusive"`
	TopPaths     []ExposureResult `json:"top_paths"`
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
	EvidenceReferences           []EvidenceReference `json:"evidence_refs"`
}

type AssessCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
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
	RerunCommands      []string                 `json:"rerun_commands"`
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
	Target  string `json:"target,omitempty"`
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Source  string `json:"source,omitempty"`
	Summary string `json:"summary"`
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
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Source  string `json:"source,omitempty"`
	Summary string `json:"summary"`
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
	ID                string      `json:"id"`
	Title             string      `json:"title"`
	Status            Status      `json:"status"`
	ProofMode         ProofMode   `json:"proof_mode"`
	Runtimes          []string    `json:"runtimes,omitempty"`
	PathNodes         []string    `json:"path_nodes"`
	PathEdges         []string    `json:"path_edges"`
	Observation       Observation `json:"observation"`
	ControlsBreakPath []string    `json:"controls_break_path,omitempty"`
	WhyItMatters      string      `json:"why_it_matters"`
	WhatWasTested     string      `json:"what_was_tested"`
	Limitations       []string    `json:"limitations"`
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
