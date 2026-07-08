package storylab

import (
	"path/filepath"
	"testing"
)

func TestListStories(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "storylab"))
	if err != nil {
		t.Fatal(err)
	}
	stories, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(stories) != 10 {
		t.Fatalf("story count = %d, want 10", len(stories))
	}
	seen := map[string]bool{}
	for _, story := range stories {
		seen[story.Manifest.ID] = true
	}
	for _, id := range []string{"local-agent-secret-exposed", "mutable-tool-launch-exposed", "data-egress-chain-exposed", "data-egress-chain-protected", "data-egress-chain-inconclusive"} {
		if !seen[id] {
			t.Fatalf("missing story %s", id)
		}
	}
	for i := 1; i < len(stories); i++ {
		if stories[i-1].Manifest.ID > stories[i].Manifest.ID {
			t.Fatalf("stories not sorted")
		}
	}
}
