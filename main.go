package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modPSAPI                 = windows.NewLazyDLL("psapi.dll")
	procEnumProcesses        = modPSAPI.NewProc("EnumProcesses")
	procEnumProcessModules   = modPSAPI.NewProc("EnumProcessModules")
	procGetModuleFileNameExW = modPSAPI.NewProc("GetModuleFileNameExW")
)

// white list : (win basic dll basename)
var safeDLLs = map[string]bool{
	"kernel32.dll": true,
	"user32.dll":   true,
	"ntdll.dll":    true,
	"msvcrt.dll":   true,
	"advapi32.dll": true,
}


// store process and dll info
type ProcessInfo struct {
	PID       uint32
	Name      string
	DLLs      []DLLInfo
}

// DLL detail
type DLLInfo struct {
	Path      string
	IsHookable bool
	Score     int    // Score（0-100）
	Reason    string
}


// get process list
func getProcesses() ([]uint32, error) {
	var pids [1024]uint32
	var bytesReturned uint32
	const size = uint32(unsafe.Sizeof(pids[0])) * uint32(len(pids))

	ret, _, err := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("EnumProcesses failed: %v", err)
	}

	numPIDs := bytesReturned / uint32(unsafe.Sizeof(pids[0]))
	return pids[:numPIDs], nil
}

// enum dll that loaded by process

func getDLLs(pid uint32) ([]DLLInfo, string, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, "", fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	var hMods [1024]windows.Handle
	var cbNeeded uint32
	ret, _, err := procEnumProcessModules.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&hMods[0])),
		uintptr(unsafe.Sizeof(hMods)),
		uintptr(unsafe.Pointer(&cbNeeded)),
	)
	if ret == 0 {
		return nil, "", nil // skip if unaccessable
	}

	numMods := cbNeeded / uint32(unsafe.Sizeof(hMods[0]))
	dlls := make([]DLLInfo, 0, numMods)


	// get process name: (first module is EXE)
	var exeName [windows.MAX_PATH]uint16
	ret, _, _ = procGetModuleFileNameExW.Call(
		uintptr(hProcess),
		uintptr(hMods[0]),
		uintptr(unsafe.Pointer(&exeName[0])),
		windows.MAX_PATH,
	)
	procName := syscall.UTF16ToString(exeName[:])

	// DLL enumeration
	for i := uint32(0); i < numMods; i++ {
		var dllName [windows.MAX_PATH]uint16
		ret, _, _ = procGetModuleFileNameExW.Call(
			uintptr(hProcess),
			uintptr(hMods[i]),
			uintptr(unsafe.Pointer(&dllName[0])),
			windows.MAX_PATH,
		)
		if ret == 0 {
			continue
		}
		path := syscall.UTF16ToString(dllName[:])
		dll := analyzeDLL(path)
		dlls = append(dlls, dll)
	}

	return dlls, procName, nil
}

// analyse DLL hookable and risk

func analyzeDLL(path string) DLLInfo {
	dll := DLLInfo{Path: path}
	lowerPath := strings.ToLower(path)
	base := strings.ToLower(filepath.Base(path))

	// white list check
	if safeDLLs[base] {
		dll.Reason = "Known safe DLL"
		return dll
	}

	// 1: non standard path
	if !strings.HasPrefix(lowerPath, `c:\windows\`) && !strings.HasPrefix(lowerPath, `c:\program files\`) {
		dll.IsHookable = true
		dll.Score += 50
		dll.Reason += "Non-standard path; "
	}

	// 2: common (known) hook target 
	if strings.Contains(base, "kernel32") || strings.Contains(base, "user32") || strings.Contains(base, "ntdll") {
		dll.IsHookable = true
		dll.Score += 30
		dll.Reason += "Common hook target; "
	}

	
	// 3: easy check for significant
	if strings.HasSuffix(base, ".dll") && strings.Contains(base, "temp") || strings.Contains(base, "unknown") {
		dll.Score += 20
		dll.Reason += "Suspicious name; "
	}

	if dll.IsHookable && dll.Reason == "" {
		dll.Reason = "Potential hook risk"
	}
	return dll
}

func main() {
	pids, err := getProcesses()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get processes: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Scanning running proesses for hookable and risky DLLs...")
	for _, pid := range pids {
		dlls, procName, err := getDLLs(pid)
		if err != nil || len(dlls) == 0 {
			continue
		}

		
		// output if hookable DLL or high scores are there
		hasRisk := false
		for _, dll := range dlls {
			if dll.IsHookable || dll.Score > 0 {
				hasRisk = true
				break
			}
		}
		if !hasRisk {
			continue
		}

		fmt.Printf("\nProcess: %s (PID: %d)\n", procName, pid)
		for _, dll := range dlls {
			if dll.IsHookable || dll.Score > 0 {
				fmt.Printf("  DLL: %s [Hookable: %v, Score: %d, Reason: %s]\n", 
					dll.Path, dll.IsHookable, dll.Score, strings.TrimSuffix(dll.Reason, "; "))
			}
		}
	}
}
