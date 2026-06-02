package scan

import "time"

const SchemaVersion = "ariadne/v1"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceInferred  Confidence = "inferred"
	ConfidenceUnknown   Confidence = "unknown"
)

type ScanMode string

const (
	ModeRepo     ScanMode = "repo"
	ModeEndpoint ScanMode = "endpoint"
	ModeDevbox   ScanMode = "devbox"
)

type Report struct {
	SchemaVersion  string        `json:"schema_version"`
	ScannerVersion string        `json:"scanner_version"`
	ScanID         string        `json:"scan_id"`
	ScanMode       ScanMode      `json:"scan_mode"`
	Platform       string        `json:"platform"`
	StartedAt      time.Time     `json:"started_at"`
	CompletedAt    time.Time     `json:"completed_at"`
	Redaction      RedactionInfo `json:"redaction"`
	Repo           RepoContext   `json:"repo"`
	Agents         []Agent       `json:"agents"`
	MCPServers     []MCPServer   `json:"mcp_servers"`
	Findings       []Finding     `json:"findings"`
	AttackPaths    []AttackPath  `json:"attack_paths"`
	Remediations   []Remediation `json:"remediations"`
	Suppressions   []Suppression `json:"suppressions"`
	Warnings       []string      `json:"warnings"`
}

type RedactionInfo struct {
	Level                  string `json:"level"`
	SensitivePathsIncluded bool   `json:"sensitive_paths_included"`
}

type RepoContext struct {
	Root                  string   `json:"root"`
	Remote                string   `json:"remote"`
	Branch                string   `json:"branch"`
	Tier                  string   `json:"tier"`
	InstructionFiles      []string `json:"instruction_files"`
	DevcontainerPresent   bool     `json:"devcontainer_present"`
	RunningInContainer    bool     `json:"running_in_container"`
	DevcontainerRiskHints []string `json:"devcontainer_risk_hints"`
}

type Agent struct {
	Kind                string   `json:"kind"`
	ConfigSources       []string `json:"config_sources"`
	ManagedEvidence     []string `json:"managed_evidence"`
	ManagedVerification string   `json:"managed_verification"`
	PermissionMode      string   `json:"permission_mode"`
	SandboxMode         string   `json:"sandbox_mode"`
	ApprovalPolicy      string   `json:"approval_policy"`
	NetworkAccess       string   `json:"network_access"`
	DangerousIndicators []string `json:"dangerous_indicators"`
	DenyReadPatterns    []string `json:"deny_read_patterns"`
	AuditTelemetryHints []string `json:"audit_telemetry_hints"`
	MCPServerNames      []string `json:"mcp_server_names"`
}

type MCPServer struct {
	Name                string   `json:"name"`
	Source              string   `json:"source"`
	Transport           string   `json:"transport"`
	CommandOrURL        string   `json:"command_or_url"`
	LaunchMechanism     string   `json:"launch_mechanism"`
	PackagePinned       string   `json:"package_pinned"`
	RiskClassifications []string `json:"risk_classifications"`
	FilesystemRoots     []string `json:"filesystem_roots"`
	ApprovedEvidence    string   `json:"approved_evidence"`
}

type Finding struct {
	ID                 string     `json:"id"`
	RuleID             string     `json:"rule_id"`
	Title              string     `json:"title"`
	Severity           Severity   `json:"severity"`
	Confidence         Confidence `json:"confidence"`
	EvidenceSource     string     `json:"evidence_source"`
	EvidenceKind       string     `json:"evidence_kind"`
	ScanMode           ScanMode   `json:"scan_mode"`
	Platform           string     `json:"platform"`
	AffectedAsset      string     `json:"affected_asset"`
	WhyItMatters       string     `json:"why_it_matters"`
	RuntimeLimitations string     `json:"runtime_limitations"`
	RemediationRefs    []string   `json:"remediation_refs"`
	Suppressed         bool       `json:"suppressed"`
}

type AttackPath struct {
	ID                  string     `json:"id"`
	Title               string     `json:"title"`
	Severity            Severity   `json:"severity"`
	Confidence          Confidence `json:"confidence"`
	LinkedFindings      []string   `json:"linked_findings"`
	Preconditions       []string   `json:"preconditions"`
	CredibleAbuseStory  string     `json:"credible_abuse_story"`
	WhyItMatters        string     `json:"why_it_matters"`
	WhatWouldReduceRisk []string   `json:"what_would_reduce_risk"`
	RuntimeLimitations  string     `json:"runtime_limitations"`
}

type Remediation struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	AppliesTo        string   `json:"applies_to"`
	Snippet          string   `json:"snippet"`
	ManualSteps      []string `json:"manual_steps"`
	BehavioralImpact string   `json:"behavioral_impact"`
}

type Suppression struct {
	FindingID string    `json:"finding_id"`
	Scope     string    `json:"scope"`
	Owner     string    `json:"owner"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
	Expired   bool      `json:"expired"`
	Source    string    `json:"source"`
}

type Options struct {
	Mode                  ScanMode
	Path                  string
	Format                string
	Out                   string
	FailOn                Severity
	IncludeSensitivePaths bool
	PreviewCollection     bool
}
