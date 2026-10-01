package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testRun(t *testing.T, mode string) *RunRecorder {
	t.Helper()
	r, err := startRecordedRun(t.TempDir(), mode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { activeRun.CompareAndSwap(r, nil); r.Finish(nil) })
	return r
}
func readManifest(t *testing.T, r *RunRecorder) RunManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.Root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m RunManifest
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func testSource() Source {
	return Source{PID: 42, StartTicks: "123", BootID: "boot-a", ModulePath: "/data/libsame.so", Base: "0x1000"}
}

func TestRunRecordsConcurrentArtifactsAndPartialStatus(t *testing.T) {
	r := testRun(t, "dumpso")
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := filepath.Join(r.Root, "dumps", string(rune('a'+i)))
			if err := writeArtifact(name, []byte("hello"), "so", "complete", testSource()); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	recordFailure("dex", Source{}, os.ErrNotExist)
	if err := r.Finish(nil); err != nil {
		t.Fatal(err)
	}
	m := readManifest(t, r)
	if len(m.Artifacts) != 13 || m.Status != "partial" || m.Ended == "" {
		t.Fatalf("bad run: %+v", m)
	}
	seen := map[string]bool{}
	for _, a := range m.Artifacts {
		if seen[a.ID] {
			t.Fatal("duplicate ID")
		}
		seen[a.ID] = true
	}
	b, _ := os.ReadFile(filepath.Join(r.Root, "events.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 13 {
		t.Fatal("lost events")
	}
	for _, line := range lines {
		var a Artifact
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAutomaticSymbolsVerifyIdentityAndContent(t *testing.T) {
	r := testRun(t, "dumpso")
	src := testSource()
	so := filepath.Join(r.Root, "dumps", "libsame.so")
	sym := filepath.Join(r.Root, "symbols", "map.txt")
	if err := writeArtifact(so, soWithDynamicSegment(), "so", "complete", src); err != nil {
		t.Fatal(err)
	}
	if err := writeArtifact(sym, []byte("0x80 nativeFoo\n"), "jni_symbols", "complete", src); err != nil {
		t.Fatal(err)
	}
	syms, ids, err := recordedSymbols(so)
	if err != nil || len(syms) != 1 || len(ids) != 1 {
		t.Fatalf("routing: %v %v %v", syms, ids, err)
	}
	for _, field := range []string{"pid", "start", "boot", "path", "base", "unknown"} {
		other := src
		switch field {
		case "pid":
			other.PID++
		case "start":
			other.StartTicks = "999"
		case "boot":
			other.BootID = "other"
		case "path":
			other.ModulePath = "/other/libsame.so"
		case "base":
			other.Base = "0x2000"
		case "unknown":
			other.IdentityError = "unavailable"
		}
		if sameModule(src, other) {
			t.Fatal("matched different identity", field)
		}
	}
	if err := os.WriteFile(sym, []byte("0x90 changed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = recordedSymbols(so); err == nil {
		t.Fatal("accepted changed symbols")
	}
}

func TestRepairRecordsInputsAndFallback(t *testing.T) {
	r := testRun(t, "dumpso")
	in := filepath.Join(r.Root, "dumps", "libsame.so")
	if err := writeArtifact(in, minimalSo(), "so", "partial", testSource()); err != nil {
		t.Fatal(err)
	}
	if err := FixSoDirectory(r.Root, nil, ""); err != nil {
		t.Fatal(err)
	}
	m := readManifest(t, r)
	if len(m.Artifacts) != 2 {
		t.Fatalf("artifacts=%d", len(m.Artifacts))
	}
	a := m.Artifacts[1]
	if a.Operation != "header_only" || a.Status != "degraded" || len(a.Inputs) != 1 || a.Inputs[0] != m.Artifacts[0].ID {
		t.Fatalf("missing lineage: %+v", a)
	}
}

func TestManualRecordedSymbolsNeverFallBackToFilename(t *testing.T) {
	r := testRun(t, "dump")
	src := testSource()
	so := filepath.Join(r.Root, "libsame.so")
	sym := filepath.Join(r.Root, "symbols.txt")
	if err := writeArtifact(sym, []byte("0x80 nativeFoo\n"), "jni_symbols", "complete", src); err != nil {
		t.Fatal(err)
	}
	other := src
	other.PID++
	if err := writeArtifact(so, soWithDynamicSegment(), "so", "complete", other); err != nil {
		t.Fatal(err)
	}
	syms, _, err := routeSymbolFile(so, sym, []InjectedSym{{Name: "nativeFoo", Value: 128}}, "")
	if err != nil || len(syms) != 0 {
		t.Fatalf("cross-process injection: %v %v", syms, err)
	}
	old := filepath.Join(t.TempDir(), "libsame.so")
	writeTestFile(t, old, minimalSo())
	if _, _, err = routeSymbolFile(old, sym, nil, ""); err == nil {
		t.Fatal("recorded symbols accepted untracked SO")
	}
}

func TestDexPathsSeparateProcessAndLifetime(t *testing.T) {
	a := dexIdentity{PID: 1, StartTicks: "10", BootID: "boot", Begin: 4096}
	b := a
	b.PID = 2
	c := a
	c.StartTicks = "20"
	if dexArtifactPath("out", a, 112, ".dex") == dexArtifactPath("out", b, 112, ".dex") || dexArtifactPath("out", a, 112, ".dex") == dexArtifactPath("out", c, 112, ".dex") {
		t.Fatal("colliding DEX paths")
	}
}
func TestProcStatNameWithParenthesis(t *testing.T) {
	stat := "42 (name ) with spaces) S " + strings.Repeat("0 ", 18) + "12345 0"
	got, err := parseStartTicks(stat)
	if err != nil || got != "12345" {
		t.Fatalf("start ticks: %s %v", got, err)
	}
}

func TestRunRejectsCorruptManifestAndJournalFailure(t *testing.T) {
	r := testRun(t, "dump")
	path := filepath.Join(r.Root, "one.dex")
	writeTestFile(t, path, []byte("data"))
	writeTestFile(t, filepath.Join(r.Root, "manifest.json"), []byte("broken"))
	if _, _, err := findArtifact(path); err == nil {
		t.Fatal("corrupt manifest accepted")
	}
	r.events.Close()
	if err := writeArtifact(path, []byte("data"), "dex", "complete", Source{}); err == nil {
		t.Fatal("journal error hidden")
	}
	if err := r.Finish(nil); err == nil {
		t.Fatal("run succeeded after journal failure")
	}
}

func TestSeparateRepairRunKeepsOriginalInputLineage(t *testing.T) {
	capture := testRun(t, "dump")
	in := filepath.Join(capture.Root, "dumps", "dex_1_70.dex")
	codes := filepath.Join(capture.Root, "dumps", "dex_1_70_code.json")
	if err := writeArtifact(in, minimalDex(), "dex", "complete", testSource()); err != nil {
		t.Fatal(err)
	}
	if err := writeArtifact(codes, []byte("[]"), "dex_code", "complete", testSource()); err != nil {
		t.Fatal(err)
	}
	original := readManifest(t, capture)
	if err := capture.Finish(nil); err != nil {
		t.Fatal(err)
	}
	activeRun.CompareAndSwap(capture, nil)
	repair, err := startRecordedRun(filepath.Join(capture.Root, "records"), "fix")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { activeRun.CompareAndSwap(repair, nil); repair.Finish(nil) }()
	if err := FixDexDirectory(capture.Root); err != nil {
		t.Fatal(err)
	}
	m := readManifest(t, repair)
	if len(m.Artifacts) != 1 || len(m.Artifacts[0].Inputs) != 2 || m.Artifacts[0].Inputs[0] != original.Artifacts[0].ID {
		t.Fatalf("lost original input: %+v", m.Artifacts)
	}
	if strings.HasPrefix(m.Artifacts[0].Path, "..") {
		t.Fatal("repair escaped its run")
	}
	after := readManifest(t, capture)
	if len(after.Artifacts) != 2 || after.Status != "completed" {
		t.Fatal("modified original run")
	}
}

func TestAutomaticSymbolRoutingInjectsMatchingLibraryOnly(t *testing.T) {
	r := testRun(t, "dumpso")
	src := testSource()
	a := filepath.Join(r.Root, "dumps", "a", "libsame.so")
	b := filepath.Join(r.Root, "dumps", "b", "libsame.so")
	other := src
	other.StartTicks = "456"
	for path, s := range map[string]Source{a: src, b: other} {
		if err := writeArtifact(path, soWithDynamicSegment(), "so", "complete", s); err != nil {
			t.Fatal(err)
		}
	}
	sym := filepath.Join(r.Root, "symbols", "map.txt")
	if err := writeArtifact(sym, []byte("0x80 nativeFoo\n"), "jni_symbols", "complete", src); err != nil {
		t.Fatal(err)
	}
	if err := FixSoDirectory(r.Root, nil, ""); err != nil {
		t.Fatal(err)
	}
	m := readManifest(t, r)
	var matched, unmatched bool
	for _, a := range m.Artifacts {
		if a.Kind != "fixed_so" {
			continue
		}
		if a.Source.StartTicks == src.StartTicks {
			matched = len(a.Inputs) == 2
		} else {
			unmatched = len(a.Inputs) == 1
		}
	}
	if !matched || !unmatched {
		t.Fatalf("wrong repair linkage: %+v", m.Artifacts)
	}
}
