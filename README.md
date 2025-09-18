# 🔒 AppGate

AppGate is a Windows command‑line utility written in modern C++17 that manages application network access using the Windows Filtering Platform (WFP). It helps you identify apps using the network and block or unblock them preemptively by executable path.

Key capabilities
- 📡 List processes currently using the network (grouped by PID with CSV of ports)
- 🧭 Enumerate installed applications (Registry, UWP, filesystem, running processes)
- 🚫/✅ Block or unblock applications by path or PID using WFP AppID filters
- 🧰 Show and remove rules created during the session

Supported platforms: Windows 10/11 (x64)
Build toolchain: MSVC + CMake (≥ 3.15) + Ninja

---

## 📸 Demo (CLI)
```
===================================================
  ___              _____       _       
 / _ \            |  __ \     | |      
/ /_\ \_ __  _ __ | |  \/ __ _| |_ ___ 
|  _  | '_ \| '_ \| | __ / _` | __/ _ \
| | | | |_) | |_) | |_\ \ (_| | ||  __/
\_| |_/ .__/| .__/ \____/\__,_|\__\___|
      | |   | |                        
      |_|   |_|                        
                     AppGate
        Application Network Access Controller
=====================================================

1. List processes using network
2. List installed applications
3. Block process (by PID or Path)
4. Unblock process (by PID or Path)
5. Show active rules
6. Delete rule by serial number
7. Delete all rules created by this program
0. Exit
```

---

## 🧠 Overview
AppGate opens a dynamic WFP session and adds allow/deny rules tied to a dedicated sublayer. Rules match applications by their AppID (derived from the executable path) and protocol. This allows proactive (path‑based) enforcement before a process starts.

Typical scenarios
- 🔍 Identify which apps are actively connected and on which ports
- ⛔ Block a specific program from any network access, inbound/outbound
- 🛡️ Prepare path‑based blocks for software you do not want to access the network

## 🏗️ Architecture
- WFP session: `FWPM_SESSION_FLAG_DYNAMIC`; rules are removed when the tool exits
- Sublayer: custom sublayer for AppGate
- Layers and conditions used:
  - Layers: `ALE_AUTH_CONNECT_V4/V6` (outbound), `ALE_AUTH_RECV_ACCEPT_V4/V6` (inbound)
  - Conditions: `ALE_APP_ID` (from `FwpmGetAppIdFromFileName0`), `IP_PROTOCOL` (TCP, UDP)
- Discovery:
  - Network processes: `GetExtendedTcpTable` (IPv4/IPv6)
  - Installed apps: Registry Uninstall keys, Start Menu shortcuts, filesystem scan, running processes, UWP via PowerShell
- Encoding: wide‑string (UTF‑16) for WFP/AppID; UTF‑8 for display

## 🧰 Requirements
- Windows 10/11 (x64)
- Visual Studio 2019/2022 with “Desktop development with C++”
- Windows 10/11 SDK (installed with VS)
- CMake 3.15+ and Ninja
- PowerShell (built‑in) for UWP package enumeration

## ⬇️ Get the source
- Clone (recommended):
```bash
git clone https://github.com/MAS191/AppGate.git
cd AppGate
```
- Or download ZIP: GitHub → Code → Download ZIP, then extract.

## 🛠️ Build
Use a “Developer Command Prompt for VS (x64)” to ensure MSVC and the Windows SDK are on PATH.

Ninja (recommended)
```bat
mkdir build && cd build
cmake -G Ninja ..
ninja
```
Visual Studio generator (alternative)
```bat
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
```
Output
- Ninja: `build\AppGate.exe`
- VS: `build\Release\AppGate.exe`

## 🔐 Run (Administrator)
WFP requires elevation. Launch in one of the following ways:
- File Explorer: Right‑click `AppGate.exe` → Run as administrator
- PowerShell (from the `build` folder):
  ```powershell
  Start-Process -FilePath .\AppGate.exe -Verb RunAs
  ```
- Command Prompt: open the terminal itself as Administrator, then run `AppGate.exe`

If you see `Failed to initialize WFP engine. Run as Administrator.`, the process is not elevated.

## 🚀 Quick usage
On launch, a menu appears. The most common actions:
- 1️⃣ List processes using network: one row per PID with CSV local/remote ports
- 2️⃣ List installed applications: aggregated from registry/UWP/filesystem/processes; select a row to block/unblock by path
- 3️⃣/4️⃣ Block/Unblock by PID or by full path directly
- 5️⃣–7️⃣ Inspect or delete rules created by AppGate in this session

See the full guide in `AppGate/usage.md` for examples and details.

## 🛠 Troubleshooting
- Build fails due to compiler/SDK not found: use a Developer Command Prompt (x64) and ensure the Windows SDK is installed
- Initialization error: run elevated; verify the “Base Filtering Engine (BFE)” service is running
- UWP apps missing: PowerShell must be available; per‑process `-ExecutionPolicy Bypass` is used, but enterprise policy might restrict this
- Non‑ASCII paths display incorrectly: switch console to UTF‑8 with `chcp 65001`
- No entries in process list: only active TCP connections are listed; idle or UDP‑only processes may not appear

## 🗂️ Project layout
- `main.cpp` — CLI entry point and menu
- `ProcessManager.h/.cpp` — Network process enumeration (TCP v4/v6), grouped output
- `InstalledAppsManager.h/.cpp` — Installed app discovery (Registry, UWP, filesystem, processes)
- `FirewallManager.h/.cpp` — WFP engine/session/sublayer and filter management
- `Utils.h/.cpp` — Helpers (GUID, error, formatting, conversions)
- `ApplicationInfo.h` — Installed application model
- `CMakeLists.txt` — Build configuration

## 📄 License
MIT — see `AppGate/LICENSE`.

