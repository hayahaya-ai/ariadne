package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	args := os.Args[1:]
	if bin := filepath.Join("ariadne-prove", "bin", "ariadne"); executableExists(bin) {
		run(bin, args...)
		return
	}
	if sourceExists(filepath.Join("ariadne-prove", "cmd", "ariadne")) {
		runInDir("ariadne-prove", "go", append([]string{"run", "./cmd/ariadne"}, args...)...)
		return
	}
	fmt.Fprintln(os.Stderr, `ariadne: the active CLI lives in ariadne-prove.

From a source checkout:
  make build
  ./ariadne-prove/bin/ariadne help

Install:
  GOBIN="$HOME/.local/bin" go install github.com/hayahaya-ai/ariadne/ariadne-prove/cmd/ariadne@latest`)
	os.Exit(2)
}

func executableExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func sourceExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func run(name string, args ...string) {
	runInDir("", name, args...)
}

func runInDir(dir string, name string, args ...string) {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(), "ARIADNE_COMMAND=./bin/ariadne")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ariadne: %v\n", err)
		os.Exit(2)
	}
}
