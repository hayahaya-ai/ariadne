# Semantic parser spec — Claude Code & Codex permission semantics

Replaces keyword (`strings.Contains`) detection for the two flagship runtimes with
structured parsing. Read `docs/northstar.md` and `CLAUDE.md` (house rule #2) first.

## Why this exists (the bug we are killing)

`collectClaudeSettings` today runs `strings.Contains(lowercasedText, "bash(*)")` and
friends. Two concrete failures this produces:

1. **allow/deny blindness.** `{"permissions":{"deny":["Bash(*)"]}}` — a *hardening*
   config — trips the `bash(*)` check and is graded as broad-local **authority**, the
   exact opposite of the truth.
2. **comment/string bleed.** `bypassPermissions` mentioned in a JSON string value, or
   `network_access = false` inside a `#`-comment or a commented-out TOML line, is read as
   live configuration.

The fix: parse the real structure, then grade off typed fields.

## Scope (decisive — do not exceed)

IN scope — the verdict-feeding detection in `collectClaudeSettings` and
`collectCodexConfig`, and the security helpers they call:
`networkRestricted`, `networkEnabled`, `declaresSecretDeny`, `broadLocalAgentConfig`
usage on Claude/Codex text. These must key off parsed structure.

OUT of scope — the frozen 20-boundary zero-trust catalog
(`collectRuntimeSecurityControls` and its `*Configured(text)` helpers) as used by the
**generic** runtimes (cursor, windsurf, aider, …) and the `.ariadne/*` policy parsers.
Do not rewrite those.

DECISION — Claude and Codex will **stop calling `collectRuntimeSecurityControls`** on raw
text. Instead, the two verdict-relevant ZT controls that are actually determinable from
real config — `control:scoped-permissions` and `control:deny-by-default-permissions` —
are emitted from parsed struct fields (see below). This removes a class of false
positives (the keyword catalog currently fires ZT controls like `cryptographic-identity`
on any Claude/Codex file containing a matching substring). If removing that call breaks an
existing test, report it to the coordinator — do not restore keyword behavior to make a
test pass; the test may be asserting a false positive we are intentionally removing.

## New package: `internal/agentconfig`

Zero external dependencies. Two parsers returning typed structs; pure and total (never
panic; malformed input yields a zero-value struct plus `ok=false`, and the collector
falls back to recording the runtime with no authorities — never to keyword scanning).

### `ParseClaudeSettings(data []byte) (ClaudeSettings, bool)`

Real JSON parse (`encoding/json`) of `.claude/settings.json` / `settings.local.json`.

```go
type ClaudeSettings struct {
    DefaultMode         string        // "" if absent; e.g. "default", "acceptEdits", "bypassPermissions"
    Allow               []PermRule
    Deny                []PermRule
    Ask                 []PermRule
    HasInlineCredential bool          // true iff a credential-shaped JSON key (top-level or nested one level under "permissions") has a non-empty string value
}
type PermRule struct {
    Raw   string // original, e.g. "Bash(*)", "Read(~/.aws/**)", "WebFetch(domain:x)"
    Tool  string // parsed head, e.g. "Bash", "Read", "WebFetch", "WebSearch" (case preserved)
    Scope string // inside the parens, e.g. "*", "~/.aws/**", "domain:x"; "" if none
}
```

- Parse `permissions.allow` / `.deny` / `.ask` as `[]string`, each split into
  `Tool` + `Scope` by the first `(` … trailing `)`. A bare string (no parens) → Tool=whole
  string, Scope="".
- `defaultMode` read as a string field under `permissions` (Claude's location) OR top
  level — check `permissions.defaultMode` first, then `defaultMode`.
- Unknown/extra keys ignored. Comments are not valid JSON — a settings file with `//`
  comments will fail JSON parse → `ok=false` (acceptable; real Claude settings are strict
  JSON).
- `HasInlineCredential` is set by a second, generic decode into
  `map[string]json.RawMessage` (top-level, and one level under `permissions`) — the fixed
  `rawClaudeSettings` struct above only models the keys agentconfig already understands
  and would silently drop an arbitrary key like `apiKeyHelper`. A key counts iff its name
  matches `isCredentialKeyName` (see below) AND its JSON value type-checks as a non-empty
  string. This is real JSON key/value inspection, never a substring scan of file bytes.

### `ParseCodexConfig(data []byte) (CodexConfig, bool)`

Hand-rolled **minimal TOML** parse of `.codex/config.toml` / `requirements.toml`. Support
only the subset below; ignore everything else. Must correctly handle: `#` line comments
(strip from `key = value` position onward when the `#` is outside a string), fully
commented-out lines (ignored), bare and quoted string values, booleans, and inline arrays
of strings. Do **not** treat text inside `# comments` or inside string values as keys.

```go
type CodexConfig struct {
    SandboxMode         string   // e.g. "read-only", "workspace-write", "danger-full-access"; "" if absent
    ApprovalPolicy      string   // e.g. "never", "on-request", "on-failure", "untrusted"; "" if absent
    NetworkAccess       *bool    // nil if absent; parsed boolean
    DenyRead            []string // paths from deny_read / [permissions.filesystem] deny_read arrays
    HasMCPServers       bool     // true if an [mcp_servers...] table or mcp_servers key is present (as structure, not substring)
    IsRequirements      bool     // set by caller from surface kind, not parsed
    HasInlineCredential bool     // true iff a key/value line's key is credential-shaped and its value is a non-empty quoted string literal
}
```

Minimal TOML rules to implement (enough for these files, no more):
- Lines are `key = value`, `[table.header]`, blank, or comment.
- Strip a trailing `# …` comment when the `#` is not inside a quoted string.
- Values: `"quoted string"`, `bare-token` (for enum-like `sandbox_mode`), `true`/`false`,
  `[ "a", "b" ]` string arrays (may span the single line; multi-line arrays optional — if
  a needed fixture uses one, support it, else single-line is fine).
- Track current table header so `[permissions.filesystem]` + `deny_read = [...]` is
  attributed correctly. A top-level `deny_read` also counts.
- `[mcp_servers.foo]` or `[mcp_servers]` header, or a `mcp_servers` key → `HasMCPServers`.
- A key/value line's key counts as credential-shaped (`isCredentialKeyName`) with a
  non-empty quoted string value → `HasInlineCredential`. A fully commented-out line never
  reaches the key/value parser at all (see the loop in `ParseCodexConfig`), so a
  credential-named key inside a `#` comment can never set this.

### `isCredentialKeyName(name string) bool`

Shared by both parsers (package-level function in `internal/agentconfig`). A key name
counts as credential-shaped in either of two ways, matched case-insensitively:

1. **Whole-key match**: `name` with `_` stripped equals one of the credential patterns
   (also with `_` stripped). Patterns: `api_key`, `apikey`, `apikeyhelper`, `api_token`,
   `secret_key`, `client_secret`, `access_key`, `private_key`. This matches regardless of
   separator style — `api_key`, `apiKey`, and `apikey` all match; `apiKeyHelper` matches
   `apikeyhelper`.
2. **Segment match**: `name` split on `_` has a segment equal to one of the single-word
   patterns `token`, `secret`, `password`, `passwd`. This lets `refresh_token` match (its
   `token` segment) while `tokenizer_mode` does NOT (`tokenizer` != `token`).

This is a total, pure function — it never panics and never scans raw file text; it only
ever inspects an already-parsed key name.

## Grading semantics (how structs map to the model)

### Claude → authorities / boundaries / controls / external-communication

Let `allow`, `deny`, `ask` be the parsed rule lists; matching is on parsed `Tool`
(case-insensitive) and `Scope`, never raw substring.

Allow/deny cancellation is bidirectional-aware: a `deny` rule cancels an `allow` rule
for the same tool when the deny's scope is **equal to or broader than** the allow's
(exact-scope match, or a broad `deny` of scope `*`/empty cancels any narrower allow of
that tool). A narrow deny (e.g. `Bash(git)`) does NOT cancel a broad allow (`Bash(*)`).

- **broad-local authority** (`authority:broad-local`) iff `DefaultMode ==
  "bypassPermissions"` OR `allow` contains a `Bash` rule with scope `*`/empty that is
  **not** overridden by a `deny` `Bash(*)`. A `deny` Bash rule must NEVER create authority.
- **file-read authority** (`authority:file-read`) iff broad-local, OR `DefaultMode ==
  "acceptEdits"`, OR `allow` contains a `Read` rule (any scope) not fully denied.
- **local-code-execution authority** + `boundary:developer-execution-boundary` iff
  broad-local, OR `allow` contains a `Bash` rule (any scope) not denied.
- **external-communication** (via `addExternalCommunication`) iff `allow` contains a
  `WebFetch`/`WebSearch` rule, OR a `Bash` rule with scope `*`/empty (shell → curl), and
  NOT contradicted by a `deny` of the same. Network tools present only in `deny` must not
  trigger it.
- **control:network-restricted** (enforced) iff EITHER:
  1. **Strong signal:** web/network tools (`WebFetch`, `WebSearch`) appear in `deny` with
     no offsetting allow of the same tool; OR
  2. **Conservative fallback:** `DefaultMode == "default"` **AND the config grants no
     external-communication authority at all** — i.e. `claudeAllowsExternalCommunication`
     is false (no allowed `WebFetch`/`WebSearch` and no broad `Bash`).

  CRITICAL (house rule #1 — no gameable verdicts): the fallback MUST be gated on the
  *absence* of external-communication authority. A config with `DefaultMode == "default"`
  and `allow: ["Bash(*)"]` grants shell-mediated network egress (curl/wget), so it must
  NOT receive `control:network-restricted` merely because `WebFetch`/`WebSearch` are
  unlisted. Defining the fallback as the negation of `claudeAllowsExternalCommunication`
  makes it structurally impossible for one config to produce both
  `authority:external-communication` and `control:network-restricted`.
- **control:deny-secret-read** (enforced) iff `deny` contains a `Read` rule whose parsed
  `Scope` names a secret-like path — match path segments semantically against
  `.env`, `.ssh`, `.aws`, `.pem`, `secrets`, `credentials`, `id_rsa`, `.npmrc`, `.git-credentials`.
  A secret path appearing in `allow` must NOT create this control.
- **control:scoped-permissions** (enforced) iff `DefaultMode == "default"` with a
  non-empty `allow` list, OR any `deny` rule exists. (Real least-privilege signal.)
- **control:deny-by-default-permissions** (enforced) iff `DefaultMode == "default"` and
  `allow` is empty or narrowly scoped (no `*` bash), i.e. nothing runs without a prompt.
- **boundary:credential-material** (observed) iff `HasInlineCredential`. The credential
  *value* is never emitted into the boundary summary or evidence — only the fact that a
  credential-shaped key was present.

### Codex → authorities / controls / tool

- **broad-local + file-read authority** iff `SandboxMode == "danger-full-access"` OR
  `ApprovalPolicy == "never"` (approval never required). A `#`-commented value must not
  count.
- **file-read authority only** (normal) iff `SandboxMode` is `"read-only"` or
  `"workspace-write"`, OR `IsRequirements` (requirements files imply a scoped workspace),
  and not broad-local.
- **external-communication** iff `NetworkAccess != nil && *NetworkAccess == true`.
- **control:network-restricted** (enforced) iff `NetworkAccess != nil && *NetworkAccess
  == false`. `nil` (absent) is neither.
- **control:deny-secret-read** (enforced) iff `DenyRead` contains a secret-like path
  (same semantic path set as Claude).
- **control:scoped-permissions** (enforced) iff `SandboxMode` is `"read-only"` or
  `"workspace-write"`, OR `ApprovalPolicy` in {`on-request`,`on-failure`,`untrusted`}.
- **tool:mcp-configured** iff `HasMCPServers`.
- **boundary:credential-material** (observed) iff `HasInlineCredential`. The credential
  *value* is never emitted into the boundary summary or evidence — only the fact that a
  credential-shaped key was present.

Enforcement: all controls above come from real runtime config, so they are `enforced`
(the existing `appendUniqueControl` provenance-by-source already yields this for non
`.ariadne` sources — keep using it; do not hardcode).

## Adversarial fixtures (must exist; keyword logic gets them wrong)

Under `ariadne-prove/testdata/realpath/` (repo mode) or as parser unit-test inputs:

1. **claude-deny-not-allow** — `{"permissions":{"defaultMode":"default","deny":["Bash(*)","Read(~/.aws/**)","WebFetch"]}}`.
   Old keyword logic → broad-local authority + external-comm (WRONG). Correct → NO
   broad-local, NO external-comm; controls: deny-secret-read, network-restricted,
   scoped-permissions. Verdict must NOT be reckless on the MCP/secret families from this file alone.
2. **codex-commented-network** — a `config.toml` with `# network_access = true` commented
   out and a live `network_access = false`. Old `networkEnabled` substring → external-comm
   (WRONG). Correct → network-restricted, no external-comm.
3. **claude-secret-in-allow** — `{"permissions":{"allow":["Read(.env)"]}}`. Old
   `declaresSecretDeny` requires "deny"+".env"; this has ".env" but in allow — must NOT
   yield deny-secret-read, and SHOULD contribute file-read authority toward a secret path.
4. **codex-keyword-in-string** — a string value or table name containing `danger` or
   `bypass` as a substring but not as `sandbox_mode`/`approval_policy` (e.g. a project
   name `name = "danger-zone-app"`). Old substring → broad-local (WRONG). Correct → graded
   only by real `sandbox_mode`.

Each fixture ships with a story-lab expectation or a prove/verdict unit test that fails
on the old logic and passes on the new.

## Constraints

- Zero external dependencies. Package `internal/agentconfig`, parsers + unit tests there.
- `collectClaudeSettings` / `collectCodexConfig` become thin: parse → derive. No
  `strings.Contains` security decisions remain in these two functions.
- Preserve enforced-vs-attested semantics and all existing passing behavior except the
  intentional false-positive removals (report those to the coordinator).
- Deterministic output; match existing package style.
- Every change ships with a fixture + test (house rule #3). `go test ./...`,
  `make verify-first-run`, and the `verify-ariadne` skill must pass.
