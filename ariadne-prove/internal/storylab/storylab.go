package storylab

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

const ManifestName = "manifest.json"

func List(root string) ([]model.Story, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var stories []model.Story
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		story, err := Load(root, entry.Name())
		if err != nil {
			return nil, err
		}
		stories = append(stories, story)
	}
	sort.Slice(stories, func(i, j int) bool {
		return stories[i].Manifest.ID < stories[j].Manifest.ID
	})
	return stories, nil
}

func Load(root, id string) (model.Story, error) {
	storyDir := filepath.Join(root, id)
	data, err := os.ReadFile(filepath.Join(storyDir, ManifestName))
	if err != nil {
		return model.Story{}, err
	}
	var manifest model.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return model.Story{}, err
	}
	if manifest.ID == "" {
		return model.Story{}, fmt.Errorf("story %s has empty id", id)
	}
	if manifest.ID != id {
		return model.Story{}, fmt.Errorf("story directory %s has manifest id %s", id, manifest.ID)
	}
	return model.Story{Dir: storyDir, Manifest: manifest}, nil
}
