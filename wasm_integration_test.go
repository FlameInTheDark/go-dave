package dave

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWASMSmoke(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skipf("node is required for WASM smoke test: %v", err)
	}

	rootDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	goRootCmd := exec.Command("go", "env", "GOROOT")
	goRootCmd.Dir = rootDir
	goRootOutput, err := goRootCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve GOROOT: %v\n%s", err, goRootOutput)
	}
	goRoot := strings.TrimSpace(string(goRootOutput))
	wasmExecPath := filepath.Join(goRoot, "lib", "wasm", "wasm_exec.js")
	if _, err := os.Stat(wasmExecPath); err != nil {
		t.Fatalf("stat wasm_exec.js: %v", err)
	}

	tempDir := t.TempDir()
	wasmPath := filepath.Join(tempDir, "go-dave.wasm")

	buildCmd := exec.Command("go", "build", "-o", wasmPath, "./cmd/go-dave-wasm")
	buildCmd.Dir = rootDir
	buildCmd.Env = append(os.Environ(),
		"GOOS=js",
		"GOARCH=wasm",
	)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build WASM module: %v\n%s", err, output)
	}

	smokeCmd := exec.Command(nodePath, filepath.Join(rootDir, "wasm", "smoke_test.mjs"))
	smokeCmd.Dir = rootDir
	smokeCmd.Env = append(os.Environ(),
		"GO_WASM_EXEC="+wasmExecPath,
		"GO_DAVE_LOADER="+filepath.Join(rootDir, "wasm", "index.mjs"),
		"GO_DAVE_WASM="+wasmPath,
	)
	if output, err := smokeCmd.CombinedOutput(); err != nil {
		t.Fatalf("run WASM smoke test: %v\n%s", err, output)
	}
}
