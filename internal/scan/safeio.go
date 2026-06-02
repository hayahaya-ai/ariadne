package scan

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxFileSize  = 512 * 1024
	maxFileCount = 2000
)

type SafeReader struct {
	Root     string
	Warnings []string
}

func NewSafeReader(root string) *SafeReader {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	return &SafeReader{Root: filepath.Clean(abs)}
}

func (r *SafeReader) ReadFile(path string, mode ScanMode) ([]byte, error) {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(clean)
		if err != nil {
			return nil, err
		}
		if mode == ModeRepo && !isWithin(target, r.Root) {
			r.Warnings = append(r.Warnings, "skipped symlink outside scan root: "+RedactString(clean, false))
			return nil, errors.New("symlink outside scan root")
		}
		clean = target
		info, err = os.Stat(clean)
		if err != nil {
			return nil, err
		}
	}
	if info.IsDir() {
		return nil, errors.New("path is a directory")
	}
	if info.Size() > maxFileSize {
		r.Warnings = append(r.Warnings, "skipped oversized file: "+RedactString(clean, false))
		return nil, errors.New("file too large")
	}
	return os.ReadFile(clean)
}

func (r *SafeReader) Walk(root string, mode ScanMode, visit func(path string, d fs.DirEntry)) {
	count := 0
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			r.Warnings = append(r.Warnings, "walk error: "+RedactString(path, false))
			return nil
		}
		if count >= maxFileCount {
			return filepath.SkipAll
		}
		name := d.Name()
		if d.IsDir() && shouldSkipDir(name) {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 && mode == ModeRepo {
			target, err := filepath.EvalSymlinks(path)
			if err != nil || !isWithin(target, r.Root) {
				r.Warnings = append(r.Warnings, "skipped symlink outside scan root: "+RedactString(path, false))
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		count++
		visit(path, d)
		return nil
	})
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "target", "dist", "build", ".cache", ".next":
		return true
	default:
		return false
	}
}

func isWithin(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
