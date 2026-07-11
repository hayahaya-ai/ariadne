package agentconfig

import (
	"reflect"
	"testing"
)

func TestParseGitHubWorkflowUsesTriggerStructureAndJobFacts(t *testing.T) {
	workflow, ok := ParseGitHubWorkflow([]byte(`name: managed review
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  id-token: write
jobs:
  review:
    permissions:
      issues: write
    env:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
    steps:
      - uses: actions/checkout@v4
      - run: curl https://example.invalid/review
`))
	if !ok {
		t.Fatal("ParseGitHubWorkflow: ok=false")
	}
	if want := []string{"pull_request", "push"}; !reflect.DeepEqual(workflow.TriggerEvents, want) {
		t.Fatalf("trigger events = %v, want %v", workflow.TriggerEvents, want)
	}
	if workflow.TriggerLines["pull_request"] != 5 || workflow.TriggerLines["push"] != 3 {
		t.Fatalf("trigger lines = %v, want pull_request:5 push:3", workflow.TriggerLines)
	}
	if !workflow.ReferencesSecrets || !workflow.OIDCTokenWrite || !workflow.WritePermissions || !workflow.RepositoryWritePermissions {
		t.Fatalf("missing parsed sensitive facts: %+v", workflow)
	}
	if !workflow.ReadsRepository || !workflow.ExternalCommunication || !workflow.ExecutesCode {
		t.Fatalf("missing parsed job facts: %+v", workflow)
	}
}

func TestParseGitHubWorkflowDoesNotPromoteTriggerNamesFromCommentsOrScalars(t *testing.T) {
	workflow, ok := ParseGitHubWorkflow([]byte(`name: pull_request_target secret reviewer
on:
  push:
    branches: [main] # pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: "pull_request: and issue_comment: are examples"
        run: echo '${{ github.event_name }} secrets.NOT_AN_EXPRESSION id-token: write ${{ 'secrets.FAKE' }}'
`))
	if !ok {
		t.Fatal("ParseGitHubWorkflow: ok=false")
	}
	if want := []string{"push"}; !reflect.DeepEqual(workflow.TriggerEvents, want) {
		t.Fatalf("trigger events = %v, want %v", workflow.TriggerEvents, want)
	}
	if workflow.ReferencesSecrets || workflow.OIDCTokenWrite || workflow.WritePermissions {
		t.Fatalf("unrelated scalar text created sensitive facts: %+v", workflow)
	}
}

func TestParseGitHubWorkflowDistinguishesPlainAndTargetPullRequestEvents(t *testing.T) {
	plain, ok := ParseGitHubWorkflow([]byte("on: [push, pull_request]\n"))
	if !ok {
		t.Fatal("plain ParseGitHubWorkflow: ok=false")
	}
	target, ok := ParseGitHubWorkflow([]byte("on: {push: null, pull_request_target: null}\n"))
	if !ok {
		t.Fatal("target ParseGitHubWorkflow: ok=false")
	}
	if want := []string{"pull_request", "push"}; !reflect.DeepEqual(plain.TriggerEvents, want) {
		t.Fatalf("plain trigger events = %v, want %v", plain.TriggerEvents, want)
	}
	if want := []string{"pull_request_target", "push"}; !reflect.DeepEqual(target.TriggerEvents, want) {
		t.Fatalf("target trigger events = %v, want %v", target.TriggerEvents, want)
	}
}

func TestParseGitHubWorkflowRejectsStructurallyUnparsedContent(t *testing.T) {
	for _, document := range []string{
		"this is not a workflow mapping\n",
		"on: [push\n",
		"name: \"unterminated\n",
	} {
		if _, ok := ParseGitHubWorkflow([]byte(document)); ok {
			t.Fatalf("ParseGitHubWorkflow(%q) = ok, want malformed", document)
		}
	}
}
