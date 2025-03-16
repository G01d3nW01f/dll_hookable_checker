# DLL Hook Checker

A lightweight tool to identify potentially hookable DLLs loaded by running Windows processes, designed to pre-filter noise from security product false positives.

## Overview

`dll_checker` is a Go-based utility that enumerates DLLs loaded by active Windows processes and assesses their susceptibility to DLL hooking. It aims to assist security researchers and system administrators in identifying risky executables and DLLs that could be exploited by malware or attackers, while minimizing false positives often seen in security software.

## Features

- **Process Enumeration**: Lists all running processes and their loaded DLLs.
- **Hookability Analysis**: Evaluates DLLs based on:
  - Non-standard paths (e.g., outside `C:\Windows\` or `C:\Program Files\`).
  - Common hook targets (e.g., `kernel32.dll`, `user32.dll`).
  - Suspicious naming patterns.
- **Risk Scoring**: Assigns a danger score (0-100) to prioritize potentially exploitable DLLs.
- **False Positive Filtering**: Whitelists known safe DLLs (e.g., Microsoft-signed system libraries).
- **Cross-Platform Build**: Compile on Linux for Windows using Go's cross-compilation.

## Installation

### Prerequisites
- Go 1.18 or later.
- Windows environment for execution (or Wine for testing on Linux).
- MinGW-w64 (optional, for test program compilation on Linux).
- go mod tidy 
  

### Dependencies
```bash
go get golang.org/x/sys/windows
```
## CrossCompile
```bash
GOOS=windows GOARCH=amd64 go build -o dll_checker.exe
```
### sample
```bash
Scanning running processes for hookable and risky DLLs...
Process: C:\Test\testprog.exe (PID: 1234)
  DLL: C:\Test\test.dll [Hookable: true, Score: 50, Reason: Non-standard path]
  DLL: C:\Windows\System32\kernel32.dll [Hookable: true, Score: 30, Reason: Common hook target]
```
