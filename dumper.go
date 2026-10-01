//go:build arm64

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

type dexDumpHeader = bpfDexEventDataT
type methodEventHeader = bpfMethodEventDataT

var outputPath string

// 方法事件处理任务
type methodTask struct {
	identity dexIdentity
	data     []byte
}

type DexDumper struct {
	manager               *manager.Manager
	libArtPath            string
	uid                   uint32
	trace                 bool
	autoFix               bool
	executeOffset         uint64
	nterpOffset           uint64
	registerNativesOffset uint64

	// 使用sync.Map减少锁竞争
	methodSigCache sync.Map // key: process/DEX identity plus method index

	// 记录dex文件大小，便于生成文件名 dex<begin>_<size>_code.json
	dexSizesMu sync.RWMutex
	dexSizes   map[dexIdentity]uint32 // Begin -> Size

	// 方法记录使用sync.Map + 原子操作
	methodRecordsMu sync.Mutex
	methodRecords   map[dexIdentity][]MethodCodeRecord // Begin -> records

	// 分片接收状态：在Go侧重组eBPF分片
	pendingDexMu sync.Mutex
	pendingDex   map[dexIdentity]*dexRecvState // Begin -> state

	// Worker pool for parallel method event processing
	methodTaskChan chan methodTask
	workerWg       sync.WaitGroup
	stopped        atomic.Bool

	// JNI RegisterNatives capture: names for dynamically-registered native
	// methods, resolved to module offsets and written out at Stop.
	jniMu      sync.Mutex
	jniMethods []jniMethod
}

// jniMethod is one captured RegisterNatives entry. fnPtr is an absolute runtime
// address, later resolved to a module-relative offset when symbols are written.
type jniMethod struct {
	source Source
	pid    uint32
	fnPtr  uint64
	name   string
	sig    string
}

// JSON导出条目
type MethodCodeRecord struct {
	Name      string `json:"name"`
	MethodIdx uint32 `json:"method_idx"`
	CodeHex   string `json:"code"`
}

//go:embed assets/*.btf
var embeddedAssets embed.FS

// Asset 从内置资源或文件系统加载
func Asset(filename string) ([]byte, error) {
	// Try embedded assets first (support both with and without assets/ prefix)
	if data, err := embeddedAssets.ReadFile(filename); err == nil {
		return data, nil
	}
	if !strings.HasPrefix(filename, "assets/") {
		if data, err := embeddedAssets.ReadFile("assets/" + filename); err == nil {
			return data, nil
		}
	}
	// Fallback to disk for dev/use outside embedding
	return ioutil.ReadFile(filename)
}

func SetupManagerOptions() (manager.Options, error) {
	btfFile := ""
	bpfManagerOptions := manager.Options{}

	if !CheckConfig("CONFIG_DEBUG_INFO_BTF=y") {
		btfFile = FindBTFAssets()
	}

	if btfFile != "" {
		var byteBuf []byte
		var err error

		byteBuf, err = Asset("assets/" + btfFile)
		if err != nil {
			byteBuf, err = Asset(btfFile)
			if err != nil {
				log.Printf("Warning: Failed to load BTF file %s: %v", btfFile, err)
				return manager.Options{
					RLimit: &unix.Rlimit{
						Cur: unix.RLIM_INFINITY,
						Max: unix.RLIM_INFINITY,
					},
				}, nil
			}
		}

		spec, err := btf.LoadSpecFromReader(bytes.NewReader(byteBuf))
		if err != nil {
			log.Printf("Warning: Failed to parse BTF spec: %v", err)
			return manager.Options{
				RLimit: &unix.Rlimit{
					Cur: unix.RLIM_INFINITY,
					Max: unix.RLIM_INFINITY,
				},
			}, nil
		}
		log.Printf("[+] Loaded BTF spec from %s", btfFile)
		bpfManagerOptions = manager.Options{
			DefaultKProbeMaxActive: 512,
			VerifierOptions: ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{
					LogSize:     2097152,
					KernelTypes: spec,
				},
			},
			RLimit: &unix.Rlimit{
				Cur: math.MaxUint64,
				Max: math.MaxUint64,
			},
		}
	} else {
		bpfManagerOptions = manager.Options{
			DefaultKProbeMaxActive: 512,
			VerifierOptions: ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{
					LogSize: 2097152,
				},
			},
			RLimit: &unix.Rlimit{
				Cur: math.MaxUint64,
				Max: math.MaxUint64,
			},
		}
	}
	return bpfManagerOptions, nil
}

func (dd *DexDumper) setupManager() error {
	offsetExecute, offsetExecuteNterp, offsetVerifyClass, err := FindArtOffsets(dd.libArtPath, dd.executeOffset, dd.nterpOffset)
	if err != nil {
		return err
	}

	// offsets are validated inside FindArtOffsets

	// 查找所有匹配的指令序列
	pattern := []byte{0x03, 0x0C, 0x40, 0xF9, 0x5F, 0x00, 0x03, 0xEB}
	patternUAddrs, err := findPatternUAddrs(dd.libArtPath, pattern)
	if err != nil {
		log.Printf("[-] pattern scan error: %v", err)
	} else {
		log.Printf("[+] found nterp_op_invoke_* %d pattern", len(patternUAddrs))
	}

	probes := []*manager.Probe{
		{
			UID:              "execute",
			EbpfFuncName:     "uprobe_libart_execute",
			Section:          "uprobe/libart_execute",
			BinaryPath:       dd.libArtPath,
			UAddress:         offsetExecute,
			AttachToFuncName: "Execute",
		},
		{
			UID:              "executeNterp",
			EbpfFuncName:     "uprobe_libart_executeNterpImpl",
			Section:          "uprobe/libart_executeNterpImpl",
			BinaryPath:       dd.libArtPath,
			UAddress:         offsetExecuteNterp,
			AttachToFuncName: "ExecuteNterpImpl",
		},
		// {
		// 	UID:              "verifyClass",
		// 	EbpfFuncName:     "uprobe_libart_verifyClass",
		// 	Section:          "uprobe/libart_verifyClass",
		// 	BinaryPath:       dd.libArtPath,
		// 	UAddress:         offsetVerifyClass,
		// 	AttachToFuncName: "VerifyClass",
		// },
	}

	for i, addr := range patternUAddrs {
		probes = append(probes, &manager.Probe{
			UID:              fmt.Sprintf("pattern_check_%d", i),
			EbpfFuncName:     "uprobe_libart_nterpOpInvoke",
			Section:          "uprobe/libart_nterpOpInvoke",
			BinaryPath:       dd.libArtPath,
			UAddress:         addr,
			AttachToFuncName: fmt.Sprintf("nterp_op_invoke_%d", i),
		})
	}

	// RegisterNatives hook for JNI name recovery (best-effort: skipped when the
	// offset can't be located in libart — stripped builds fall back to string xref).
	if regNativesOff := FindRegisterNativesOffset(dd.libArtPath, dd.registerNativesOffset); regNativesOff != 0 {
		probes = append(probes, &manager.Probe{
			UID:              "registerNatives",
			EbpfFuncName:     "uprobe_libart_registerNatives",
			Section:          "uprobe/libart_registerNatives",
			BinaryPath:       dd.libArtPath,
			UAddress:         regNativesOff,
			AttachToFuncName: "RegisterNatives",
		})
		log.Printf("[+] JNI RegisterNatives hook enabled (libart offset 0x%x)", regNativesOff)
	} else {
		log.Printf("[-] RegisterNatives offset not found in libart; JNI name recovery disabled")
	}

	dd.manager = &manager.Manager{
		Probes: probes,
		RingbufMaps: []*manager.RingbufMap{
			{
				Map: manager.Map{
					Name: "events",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleDexEventRingBuf,
				},
			},
			{
				Map: manager.Map{
					Name: "method_events",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleMethodEventRingBuf,
				},
			},
			{
				Map: manager.Map{
					Name: "dex_chunks",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleDexChunkEventRingBuf,
				},
			},
			{
				Map: manager.Map{
					Name: "read_failures",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleReadFailureEventRingBuf,
				},
			},
			{
				Map: manager.Map{
					Name: "jni_events",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: dd.handleJniEventRingBuf,
				},
			},
		},
	}

	log.Printf("[+] offsetExecute: %x offsetExecuteNterp: %x offsetVerifyClass: %x",
		offsetExecute, offsetExecuteNterp, offsetVerifyClass)
	return nil
}

// Start 启动 DexDumper
func (dd *DexDumper) Start(ctx context.Context) error {
	// setup manager
	if err := dd.setupManager(); err != nil {
		return fmt.Errorf("failed to setup manager: %v", err)
	}

	// init manager with BPF bytecode
	options, err := SetupManagerOptions()
	if err != nil {
		return fmt.Errorf("failed to setup manager options: %v", err)
	}

	if err := dd.manager.InitWithOptions(bytes.NewReader(_BpfBytes), options); err != nil {
		return fmt.Errorf("failed to init manager: %v", err)
	}

	// config filter map
	configMap, found, err := dd.manager.GetMap("config_map")
	if err != nil {
		return fmt.Errorf("failed to get config map: %v", err)
	}
	if !found {
		return fmt.Errorf("config map not found")
	}

	config := bpfConfigT{
		Uid: dd.uid,
		Pid: 0,
	}

	if err := configMap.Put(uint32(0), config); err != nil {
		return fmt.Errorf("failed to put config: %v", err)
	}

	log.Printf("[+] Filtering on uid %d", dd.uid)

	// start manager
	if err := dd.manager.Start(); err != nil {
		return fmt.Errorf("failed to start manager: %v", err)
	}

	log.Printf("eBPF DexDumper started successfully")

	// 等待停止信号
	<-ctx.Done()

	return nil
}

// Stop 停止 DexDumper
func (dd *DexDumper) Stop() error {
	log.Printf("Stopping eBPF DexDumper")

	// 标记停止，阻止新事件进入
	dd.stopped.Store(true)

	// 先停止 manager，确保不再有新事件
	if dd.manager != nil {
		if err := dd.manager.Stop(manager.CleanAll); err != nil {
			log.Printf("Manager stop error: %v", err)
		}
	}

	// 然后关闭 worker pool
	close(dd.methodTaskChan)
	dd.workerWg.Wait()

	dd.pendingDexMu.Lock()
	for identity, pending := range dd.pendingDex {
		src := identity.source()
		src.ExpectedBytes = uint64(pending.total)
		src.ReadBytes = uint64(pending.recv)
		recordFailure("dex", src, fmt.Errorf("incomplete DEX: received %d of %d bytes", pending.recv, pending.total))
	}
	dd.pendingDexMu.Unlock()
	dd.flushJSON()
	dd.writeJniSymbols()

	// 自动修复DEX文件
	if dd.autoFix {
		log.Printf("[+] Auto-fixing DEX files...")
		if err := FixDexDirectory(outputPath); err != nil {
			log.Printf("[!] Auto-fix failed: %v", err)
			return err
		}
	}
	return nil
}

const numWorkers = 4 // 并行处理 worker 数量

func NewDexDumper(libArtPath string, uid uint32, outputDir string, trace, autoFix bool, executeOffset, nterpOffset, registerNativesOffset uint64) *DexDumper {
	outputPath = outputDir

	dd := &DexDumper{
		libArtPath:            libArtPath,
		uid:                   uid,
		trace:                 trace,
		autoFix:               autoFix,
		executeOffset:         executeOffset,
		nterpOffset:           nterpOffset,
		registerNativesOffset: registerNativesOffset,
		dexSizes:              make(map[dexIdentity]uint32),
		methodRecords:         make(map[dexIdentity][]MethodCodeRecord),
		pendingDex:            make(map[dexIdentity]*dexRecvState),
		methodTaskChan:        make(chan methodTask, 4096), // 缓冲通道
	}

	// 启动 worker pool
	for i := 0; i < numWorkers; i++ {
		dd.workerWg.Add(1)
		go dd.methodWorker()
	}

	return dd
}

// methodWorker 并行处理方法事件
func (dd *DexDumper) methodWorker() {
	defer dd.workerWg.Done()
	for task := range dd.methodTaskChan {
		dd.processMethodEvent(task.data, task.identity)
	}
}

// handleDexEventRingBuf 处理 Dex 文件事件 (RingBuffer版本)
func (dd *DexDumper) handleDexEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	buf := bytes.NewBuffer(data)
	dexHeader := dexDumpHeader{}
	if err := binary.Read(buf, binary.LittleEndian, &dexHeader); err != nil {
		log.Printf("Read dex event failed: %s", err)
		return
	}

	// 保存 dex 文件大小，供JSON导出文件名使用
	dd.dexSizesMu.Lock()
	dd.dexSizes[dexID(dexHeader.Pid, dexHeader.Begin)] = dexHeader.Size
	dd.dexSizesMu.Unlock()

	// eBPF层已开始分片发送，此处不再 process_vm_readv。
	// 仅记录大小等元信息，等待 dex_chunks 重组完成。
}

func (dd *DexDumper) handleMethodEventRingBuf(CPU int, data []byte, perfMap *manager.RingbufMap, manager *manager.Manager) {
	if dd.stopped.Load() || len(data) < int(unsafe.Sizeof(methodEventHeader{})) {
		return
	}
	var hdr methodEventHeader
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &hdr); err != nil {
		return
	}
	identity := dexID(hdr.Pid, hdr.Begin)
	// 复制数据并分发到 worker pool
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	select {
	case dd.methodTaskChan <- methodTask{data: dataCopy, identity: identity}:
	default:
		// 通道满时直接处理，避免阻塞 ringbuf
		dd.processMethodEvent(dataCopy, identity)
	}
}

// processMethodEvent 实际处理方法事件
func (dd *DexDumper) processMethodEvent(data []byte, identity dexIdentity) {
	buf := bytes.NewBuffer(data)
	methodHeader := methodEventHeader{}
	if err := binary.Read(buf, binary.LittleEndian, &methodHeader); err != nil {
		return
	}

	// Read bytecode if present
	var bytecode []byte
	if methodHeader.CodeitemSize > 0 {
		if uint64(methodHeader.CodeitemSize) > uint64(buf.Len()) {
			return
		}
		bytecode = buf.Next(int(methodHeader.CodeitemSize))
	}

	parser := dexCache.GetParser(identity)

	var methodName string

	if parser == nil {
		// 当没有dex缓存时，使用方法idx作为methodName
		methodName = fmt.Sprintf("method_idx_%d", methodHeader.MethodIndex)
	} else {
		// 使用sync.Map无锁查询缓存
		cacheKey := struct {
			Dex    dexIdentity
			Method uint32
		}{identity, methodHeader.MethodIndex}
		if cached, ok := dd.methodSigCache.Load(cacheKey); ok {
			methodName = cached.(string)
		} else {
			methodInfo, err := parser.GetMethodInfo(methodHeader.MethodIndex)
			if err != nil {
				methodName = fmt.Sprintf("method_idx_%d", methodHeader.MethodIndex)
			} else {
				methodName = methodInfo.PrettyMethod()
				// 存入缓存
				dd.methodSigCache.Store(cacheKey, methodName)
			}
		}
	}

	if methodHeader.CodeitemSize > 0 {
		if dd.trace {
			log.Printf("%s (pid=%d, dex=0x%x, method_idx=%d, art_method=0x%x, bytecode_size=%d)",
				methodName,
				methodHeader.Pid,
				methodHeader.Begin,
				methodHeader.MethodIndex,
				methodHeader.ArtMethodPtr,
				methodHeader.CodeitemSize)
		}

		// 记录到每个dex的JSON导出缓存
		if len(bytecode) > 0 {
			rec := MethodCodeRecord{
				Name:      methodName,
				MethodIdx: methodHeader.MethodIndex,
				CodeHex:   hex.EncodeToString(bytecode),
			}
			dd.methodRecordsMu.Lock()
			dd.methodRecords[identity] = append(dd.methodRecords[identity], rec)
			dd.methodRecordsMu.Unlock()
		}
	} else {
		if dd.trace {
			log.Printf("%s (pid=%d, dex=0x%x, method_idx=%d, art_method=0x%x)",
				methodName,
				methodHeader.Pid,
				methodHeader.Begin,
				methodHeader.MethodIndex,
				methodHeader.ArtMethodPtr)
		}
	}
}

func (dd *DexDumper) flushJSON() {
	dd.methodRecordsMu.Lock()
	records := dd.methodRecords
	dd.methodRecords = make(map[dexIdentity][]MethodCodeRecord)
	dd.methodRecordsMu.Unlock()

	dd.dexSizesMu.RLock()
	sizes := make(map[dexIdentity]uint32, len(dd.dexSizes))
	for k, v := range dd.dexSizes {
		sizes[k] = v
	}
	dd.dexSizesMu.RUnlock()

	for begin, recs := range records {
		if len(recs) == 0 {
			continue
		}

		size := sizes[begin]
		if size == 0 {
			if p := dexCache.GetParser(begin); p != nil {
				size = p.header.FileSize
			}
		}

		fileName := dexArtifactPath(outputPath, begin, size, "_code.json")
		data, err := json.MarshalIndent(recs, "", "  ")
		if err == nil {
			err = writeArtifact(fileName, data, "dex_code", "complete", begin.source())
		}
		if err != nil {
			log.Printf("Write JSON failed: %v", err)
		}

	}
}

func (dd *DexDumper) handleDexChunkEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	if len(data) < int(unsafe.Sizeof(bpfDexChunkEventT{})) {
		log.Printf("Dex chunk event too short: %d bytes", len(data))
		return
	}

	buf := bytes.NewBuffer(data)
	hdr := bpfDexChunkEventT{}
	if err := binary.Read(buf, binary.LittleEndian, &hdr); err != nil {
		log.Printf("Read dex chunk header failed: %s", err)
		return
	}

	if hdr.DataLen == 0 || uint64(hdr.DataLen) > uint64(buf.Len()) ||
		uint64(hdr.Offset)+uint64(hdr.DataLen) > uint64(hdr.Size) {
		log.Printf("Invalid dex chunk payload: offset=%d length=%d size=%d", hdr.Offset, hdr.DataLen, hdr.Size)
		return
	}
	payload := buf.Next(int(hdr.DataLen))

	begin := dexID(hdr.Pid, hdr.Begin)
	// A completed fallback must not be replaced by late ring-buffer chunks.
	if dexCache.GetParser(begin) != nil {
		return
	}
	dd.pendingDexMu.Lock()
	st, ok := dd.pendingDex[begin]
	if !ok {
		// init new state
		var err error
		st, err = newDexRecvState(hdr.Size)
		if err != nil {
			dd.pendingDexMu.Unlock()
			log.Printf("Invalid dex chunk: %v", err)
			return
		}
		dd.pendingDex[begin] = st
		// record size for later JSON name
		dd.dexSizesMu.Lock()
		dd.dexSizes[begin] = hdr.Size
		dd.dexSizesMu.Unlock()
	}
	if hdr.Size != st.total {
		dd.pendingDexMu.Unlock()
		log.Printf("Inconsistent dex chunk size: got %d, expected %d", hdr.Size, st.total)
		return
	}
	complete, err := st.addChunk(hdr.Offset, payload)
	if err != nil {
		dd.pendingDexMu.Unlock()
		log.Printf("Invalid dex chunk: %v", err)
		return
	}

	// completed?
	if complete {
		dataCopy := st.buf
		// finalize
		delete(dd.pendingDex, begin)
		dd.pendingDexMu.Unlock()

		if err := dexCache.AddDexFile(begin, dataCopy); err != nil {
			log.Printf("Failed to add dex file to cache: %v", err)
		}

		fileName := dexArtifactPath(outputPath, begin, hdr.Size, ".dex")
		src := begin.source()
		src.ExpectedBytes = uint64(hdr.Size)
		src.ReadBytes = uint64(len(dataCopy))
		if err := writeArtifact(fileName, dataCopy, "dex", "complete", src); err != nil {
			log.Printf("Write DEX failed: %v", err)
			return
		}

		log.Printf("Dex file saved to %s, size %d", fileName, len(dataCopy))
		return
	}
	dd.pendingDexMu.Unlock()
}

// handleJniEventRingBuf receives one RegisterNatives entry and records it for
// later resolution to a module offset.
func (dd *DexDumper) handleJniEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	if len(data) < int(unsafe.Sizeof(bpfJniMethodEventT{})) {
		return
	}
	evt := bpfJniMethodEventT{}
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &evt); err != nil {
		return
	}
	name := goCStr(evt.Name[:])
	if name == "" {
		return
	}
	src := processSource(evt.Pid, 0)
	if mods, err := ScanSoModules(int(evt.Pid), "", true, true); err == nil {
		for _, mod := range mods {
			if evt.FnPtr >= mod.Base && evt.FnPtr < mod.End {
				src.ModulePath = mod.Path
				src.Base = fmt.Sprintf("0x%x", mod.Base)
				break
			}
		}
	}
	dd.jniMu.Lock()
	dd.jniMethods = append(dd.jniMethods, jniMethod{source: src, pid: evt.Pid, fnPtr: evt.FnPtr, name: name, sig: goCStr(evt.Sig[:])})
	dd.jniMu.Unlock()
}

// goCStr converts a NUL-terminated int8 buffer (as generated for eBPF char[]
// event fields) to a Go string.
func goCStr(b []int8) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(b[i])
	}
	return string(out)
}

// writeJniSymbols uses the module identity observed at capture and writes per-module
// "offset name" files ready for `fixso --symbols`, plus a raw capture. Called at
// Stop; a no-op if nothing was captured.
func (dd *DexDumper) writeJniSymbols() {
	dd.jniMu.Lock()
	methods := append([]jniMethod(nil), dd.jniMethods...)
	dd.jniMu.Unlock()
	if len(methods) == 0 {
		return
	}

	perMod := map[string]*bytes.Buffer{}
	sources := map[string]Source{}
	raw := &bytes.Buffer{}
	seen := map[string]bool{}
	for _, m := range methods {
		key := fmt.Sprintf("%s_%x", sourceKey(m.source), m.fnPtr)
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Fprintf(raw, "%d 0x%x %s %s\n", m.pid, m.fnPtr, m.name, m.sig)
		src := m.source
		base, err := strconv.ParseUint(strings.TrimPrefix(src.Base, "0x"), 16, 64)
		if err != nil || src.ModulePath == "" || src.StartTicks == "" || src.BootID == "" || m.fnPtr < base {
			recordFailure("jni_symbols", src, fmt.Errorf("module identity unavailable at JNI capture"))
			continue
		}
		key = fmt.Sprintf("%s_%s_%s", sourceKey(src), src.Base, src.ModulePath)
		b := perMod[key]
		if b == nil {
			b = &bytes.Buffer{}
			perMod[key] = b
			sources[key] = src
		}
		fmt.Fprintf(b, "0x%x %s\n", m.fnPtr-base, m.name)

	}

	if err := writeArtifact(filepath.Join(outputPath, "symbols", "jni_symbols_raw.txt"), raw.Bytes(), "jni_raw", "complete", Source{}); err != nil {
		log.Printf("Write JNI raw failed: %v", err)
	}
	for key, b := range perMod {
		src := sources[key]
		identity := sha256.Sum256([]byte(key))
		name := fmt.Sprintf("jni_symbols_%x.txt", identity[:12])
		if err := writeArtifact(filepath.Join(outputPath, "symbols", name), b.Bytes(), "jni_symbols", "complete", src); err != nil {
			log.Printf("Write JNI symbols failed: %v", err)
		}
	}
	log.Printf("[+] Captured %d JNI method(s) across %d module(s); wrote jni_symbols_*.txt under %s (feed to: fixso --symbols)", len(seen), len(perMod), outputPath)
}

func (dd *DexDumper) handleReadFailureEventRingBuf(CPU int, data []byte, ringBuf *manager.RingbufMap, mgr *manager.Manager) {
	if len(data) < int(unsafe.Sizeof(bpfDexReadFailureT{})) {
		log.Printf("Read failure event too short: %d bytes", len(data))
		return
	}

	buf := bytes.NewBuffer(data)
	failureEvt := bpfDexReadFailureT{}
	if err := binary.Read(buf, binary.LittleEndian, &failureEvt); err != nil {
		log.Printf("Read failure event failed: %s", err)
		return
	}

	log.Printf("[dex-fallback] eBPF read miss at offset %d for dex 0x%x (pid=%d size=%d), trying process_vm_readv",
		failureEvt.FailedOffset, failureEvt.Begin, failureEvt.Pid, failureEvt.Size)

	dd.readRemoteDexFallback(failureEvt.Begin, failureEvt.Pid, failureEvt.Size, failureEvt.FailedOffset)
}

func (dd *DexDumper) readRemoteDexFallback(begin uint64, pid uint32, totalSize uint32, startOffset uint32) {
	begin = untagAddr(begin)
	identity := dexID(pid, begin)
	if dexCache.GetParser(identity) != nil {
		return
	}
	buf, err := readDexImage(begin, totalSize, func(address uintptr, dst []byte) error {
		return readMemoryRange(address, dst, func(address uintptr, dst []byte) error {
			return readRemoteMemory(pid, address, dst)
		})
	})
	if err != nil {
		recordFailure("dex", identity.source(), err)
		log.Printf("[dex-fallback] failed to read dex 0x%x (pid=%d off=%d): %v", begin, pid, startOffset, err)
		return
	}
	outSize := uint32(len(buf))
	if outSize != totalSize {
		log.Printf("[dex-fallback] resized dump 0x%x to header file_size %d", begin, outSize)
	}

	dd.pendingDexMu.Lock()
	delete(dd.pendingDex, identity)
	dd.pendingDexMu.Unlock()

	dd.dexSizesMu.Lock()
	dd.dexSizes[identity] = outSize
	dd.dexSizesMu.Unlock()

	if err := dexCache.AddDexFile(identity, buf); err != nil {
		log.Printf("Failed to add dex file to cache: %v", err)
	}

	fileName := dexArtifactPath(outputPath, identity, outSize, ".dex")
	src := identity.source()
	src.ExpectedBytes = uint64(outSize)
	src.ReadBytes = uint64(len(buf))
	if err := writeArtifact(fileName, buf, "dex", "complete", src); err != nil {
		log.Printf("Write DEX failed: %v", err)
		return
	}

	log.Printf("Dex file saved to %s (fallback readRemoteMem), size %d", fileName, len(buf))
}
