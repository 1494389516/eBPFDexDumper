package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func dexWithRepairableMethod() []byte {
	data := append(minimalDex(), make([]byte, 84)...)
	binary.LittleEndian.PutUint32(data[32:], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[96:], 1)
	binary.LittleEndian.PutUint32(data[100:], 112)
	binary.LittleEndian.PutUint32(data[136:], 144)
	copy(data[144:], []byte{0, 0, 1, 0, 0, 0, 0xb0, 1})
	binary.LittleEndian.PutUint32(data[188:], 2)
	return data
}

func TestFixDexRejectsInvalidPatchesWithoutReplacingOutput(t *testing.T) {
	for _, tc := range []struct {
		name, records string
		oversized     bool
	}{
		{"short", `[{"method_idx":0,"code":"1200"}]`, false},
		{"long", `[{"method_idx":0,"code":"12000f000000"}]`, false},
		{"odd instruction", `[{"method_idx":0,"code":"12"}]`, false},
		{"invalid hex", `[{"method_idx":0,"code":"zz"}]`, false},
		{"truncated code item", `[{"method_idx":0,"code":"12000f00"}]`, true},
		{"valid then invalid", `[{"method_idx":0,"code":"12000f00"},{"method_idx":0,"code":"00"}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in, codes, out := filepath.Join(dir, "in.dex"), filepath.Join(dir, "codes.json"), filepath.Join(dir, "out.dex")
			data := dexWithRepairableMethod()
			if tc.oversized {
				binary.LittleEndian.PutUint32(data[188:], 0xffffffff)
			}
			writeTestFile(t, in, data)
			writeTestFile(t, codes, []byte(tc.records))
			original := []byte("existing output must survive invalid repair")
			writeTestFile(t, out, original)
			if err := FixOneDex(in, codes, out); err == nil {
				t.Error("invalid patch reported success")
			}
			got, err := os.ReadFile(out)
			if err != nil || !bytes.Equal(got, original) {
				t.Errorf("output replaced on failure: %x, %v", got, err)
			}
		})
	}
}

func TestSoModuleMatchingDoesNotUseSuffixAlone(t *testing.T) {
	for _, tc := range []struct {
		name, stem string
		want       bool
	}{
		{"libfoo.so", "libfoo", true},
		{"so_123_abcd_1000_libfoo.so", "libfoo", true},
		{"so_123_abcd_1000_lib_foo.so", "lib_foo", true},
		{"other_libfoo.so", "libfoo", false},
		{"so_123_abcd_1000_other_libfoo.so", "libfoo", false},
		{"so_bad_abcd_1000_libfoo.so", "libfoo", false},
		{"so_123_invalid_1000_libfoo.so", "libfoo", false},
	} {
		if got := soMatchesModule(tc.name, tc.stem); got != tc.want {
			t.Errorf("soMatchesModule(%q,%q) = %v", tc.name, tc.stem, got)
		}
	}
}
