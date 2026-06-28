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
	SchemaVersion string           `json:"schema_version"`
	RunID         string           `json:"run_id"`
	GeneratedAt   time.Time        `json:"generated_at"`
	RunKind       string           `json:"run_kind"`
	TargetPath    string           `json:"target_path,omitempty"`
	Story         StorySummary     `json:"story"`
	Expected      ExpectedResult   `json:"expected"`
	Matched       bool             `json:"matched"`
	Mismatches    []string         `json:"mismatches,omitempty"`
	Exposure      ExposureResult   `json:"exposure"`
	Exposures     []ExposureResult `json:"exposures,omitempty"`
	Graph         Graph            `json:"graph"`
	Evidence      []Evidence       `json:"evidence"`
	Redaction     RedactionInfo    `json:"redaction"`
	Warnings      []string         `json:"warnings,omitempty"`
	Limitations   []string         `json:"limitations"`
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

type Evidence struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Grade   string `json:"grade"`
	Source  string `json:"source,omitempty"`
	Runtime string `json:"runtime,omitempty"`
	Summary string `json:"summary"`
}

type Surface struct {
	ID           string `json:"id"`
	Path         string `json:"-"`
	Runtime      string `json:"runtime"`
	Scope        string `json:"scope"`
	Category     string `json:"category"`
	Kind         string `json:"kind"`
	HandlingMode string `json:"handling_mode"`
	Source       string `json:"source"`
	Summary      string `json:"summary"`
	ApproxBytes  int64  `json:"approx_bytes,omitempty"`
	FileCount    int    `json:"file_count,omitempty"`
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
}

type ScanReport struct {
	SchemaVersion string             `json:"schema_version"`
	RunID         string             `json:"run_id"`
	GeneratedAt   time.Time          `json:"generated_at"`
	RunKind       string             `json:"run_kind"`
	Mode          string             `json:"mode"`
	Agent         string             `json:"agent"`
	Summary       ScanSummary        `json:"summary"`
	Targets       []ScanTargetResult `json:"targets"`
	Redaction     RedactionInfo      `json:"redaction"`
	Warnings      []string           `json:"warnings,omitempty"`
	Limitations   []string           `json:"limitations"`
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
