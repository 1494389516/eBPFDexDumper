//go:build arm64

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestDexChunkCaptureSeparatesProcesses(t *testing.T) {
	r := testRun(t, "dump")
	dexCache = &DexFileCache{parsers: make(map[dexIdentity]*DexParser)}
	dd := NewDexDumper("", 0, r.Root, false, false, 0, 0, 0)
	defer dd.Stop()
	data := minimalDex()
	for _, pid := range []uint32{uint32(os.Getpid()), 4000000000} {
		var buf bytes.Buffer
		hdr := bpfDexChunkEventT{Begin: 4096, Pid: pid, Size: uint32(len(data)), DataLen: uint32(len(data))}
		if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
			t.Fatal(err)
		}
		buf.Write(data)
		dd.handleDexChunkEventRingBuf(0, buf.Bytes(), nil, nil)
	}
	m := readManifest(t, r)
	if len(m.Artifacts) != 2 || m.Artifacts[0].Path == m.Artifacts[1].Path || m.Artifacts[0].Source.PID == m.Artifacts[1].Source.PID {
		t.Fatalf("mixed capture: %+v", m.Artifacts)
	}
	for _, a := range m.Artifacts {
		if _, err := os.Stat(filepath.Join(r.Root, a.Path)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJniFlushUsesCapturedSourceAfterProcessExit(t *testing.T) {
	r := testRun(t, "dump")
	dd := NewDexDumper("", 0, r.Root, false, false, 0, 0, 0)
	defer dd.Stop()
	a := testSource()
	a.PID = 4000000000
	b := a
	b.StartTicks = "different"
	dd.jniMethods = []jniMethod{
		{source: a, pid: a.PID, fnPtr: 0x1080, name: "first"},
		{source: b, pid: b.PID, fnPtr: 0x1080, name: "second"},
	}
	dd.writeJniSymbols()
	dd.jniMethods = nil
	m := readManifest(t, r)
	var maps []Artifact
	for _, a := range m.Artifacts {
		if a.Kind == "jni_symbols" {
			maps = append(maps, a)
		}
	}
	if len(maps) != 2 || maps[0].Path == maps[1].Path || maps[0].Source.StartTicks == maps[1].Source.StartTicks {
		t.Fatalf("mixed JNI sources: %+v", maps)
	}
}
