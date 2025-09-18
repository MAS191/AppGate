// ProcessManager.cpp
// Implements process and network enumeration
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <shlwapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <objbase.h>
#include <winreg.h>
#include "Models.h"
#include "Utils.h"
#include "ProcessManager.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

// Helper: narrow wide string to UTF-8 std::string
static std::string WToU8(const wchar_t* w) {
    if (!w) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    std::string s;
    s.resize(len ? len - 1 : 0);
    if (len > 0) {
        WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, NULL, NULL);
    }
    return s;
}

// Extract an executable path from a command line (handles quotes and args)
static std::wstring ExtractExeFromCmd(wchar_t* cmd) {
    if (!cmd) return L"";
    PathUnquoteSpacesW(cmd);
    PathRemoveArgsW(cmd);
    return cmd;
}

// Normalize a path: expand env vars, remove quotes/args, get full path
static std::wstring NormalizePath(const std::wstring& in) {
    if (in.empty()) return in;
    wchar_t buf[4096];
    wcsncpy_s(buf, in.c_str(), _TRUNCATE);
    PathUnquoteSpacesW(buf);
    PathRemoveArgsW(buf);
    // Expand environment variables
    wchar_t exp[4096];
    DWORD n = ExpandEnvironmentStringsW(buf, exp, _countof(exp));
    const wchar_t* src = (n > 0 && n < _countof(exp)) ? exp : buf;
    // Get full path if possible
    wchar_t full[4096];
    DWORD m = GetFullPathNameW(src, _countof(full), full, nullptr);
    if (m > 0 && m < _countof(full)) {
        return full;
    }
    return src;
}

// Resolve .lnk shortcut target path using raw COM pointers
static std::wstring ResolveShortcut(const std::wstring& lnkPath) {
    std::wstring result;
    IShellLinkW* psl = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl);
    if (FAILED(hr) || !psl) return result;
    IPersistFile* ppf = nullptr;
    hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
    if (SUCCEEDED(hr) && ppf) {
        if (SUCCEEDED(ppf->Load(lnkPath.c_str(), STGM_READ))) {
            wchar_t target[MAX_PATH] = {}; WIN32_FIND_DATAW wfd{};
            if (SUCCEEDED(psl->GetPath(target, _countof(target), &wfd, SLGP_UNCPRIORITY))) {
                result = target;
            }
        }
        ppf->Release();
    }
    psl->Release();
    return result;
}

// Helper to get process name and path
static bool GetProcessNameAndPath(DWORD pid, std::string& name, std::string& path) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    char buffer[MAX_PATH] = {0};
    if (GetModuleFileNameExA(hProcess, NULL, buffer, MAX_PATH)) {
        path = buffer;
        size_t pos = path.find_last_of("\\/");
        name = (pos != std::string::npos) ? path.substr(pos+1) : path;
        CloseHandle(hProcess);
        return true;
    }
    CloseHandle(hProcess);
    return false;
}

ProcessManager::ProcessManager() {}

std::vector<ProcessInfo> ProcessManager::ListNetworkProcesses() {
    std::vector<ProcessInfo> result;

    // IPv4 TCP
    PMIB_TCPTABLE_OWNER_PID pTcp4 = nullptr; DWORD sz4 = 0;
    if (GetExtendedTcpTable(NULL, &sz4, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcp4 = (PMIB_TCPTABLE_OWNER_PID)malloc(sz4);
        if (pTcp4 && GetExtendedTcpTable(pTcp4, &sz4, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcp4->dwNumEntries; ++i) {
                DWORD pid = pTcp4->table[i].dwOwningPid;
                std::string name, path; if (!GetProcessNameAndPath(pid, name, path)) continue;
                ProcessInfo pi; pi.pid = (int)pid; pi.name = name; pi.path = path; pi.protocol = "TCPv4";
                pi.localAddr = Utils::SockaddrToString(pTcp4->table[i].dwLocalAddr, pTcp4->table[i].dwLocalPort);
                pi.remoteAddr = Utils::SockaddrToString(pTcp4->table[i].dwRemoteAddr, pTcp4->table[i].dwRemotePort);
                result.push_back(pi);
            }
        }
        if (pTcp4) free(pTcp4);
    }

    // IPv6 TCP
    PMIB_TCP6TABLE_OWNER_PID pTcp6 = nullptr; DWORD sz6 = 0;
    if (GetExtendedTcpTable(NULL, &sz6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcp6 = (PMIB_TCP6TABLE_OWNER_PID)malloc(sz6);
        if (pTcp6 && GetExtendedTcpTable(pTcp6, &sz6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcp6->dwNumEntries; ++i) {
                DWORD pid = pTcp6->table[i].dwOwningPid;
                std::string name, path; if (!GetProcessNameAndPath(pid, name, path)) continue;
                ProcessInfo pi; pi.pid = (int)pid; pi.name = name; pi.path = path; pi.protocol = "TCPv6";
                pi.localAddr = Utils::Sockaddr6ToString(pTcp6->table[i].ucLocalAddr, pTcp6->table[i].dwLocalPort);
                pi.remoteAddr = Utils::Sockaddr6ToString(pTcp6->table[i].ucRemoteAddr, pTcp6->table[i].dwRemotePort);
                result.push_back(pi);
            }
        }
        if (pTcp6) free(pTcp6);
    }

    return result;
}

ProcessInfo ProcessManager::GetProcessByPID(int pid) {
    std::string name, path;
    if (GetProcessNameAndPath((DWORD)pid, name, path)) {
        ProcessInfo pi;
        pi.pid = pid;
        pi.name = name;
        pi.path = path;
        return pi;
    }
    return ProcessInfo();
}

std::vector<NetProcRow> ProcessManager::ListNetworkProcessesGrouped() {
    std::unordered_map<int, NetProcRow> map;

    // IPv4 TCP
    PMIB_TCPTABLE_OWNER_PID pTcp4 = nullptr; DWORD sz4 = 0;
    if (GetExtendedTcpTable(NULL, &sz4, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcp4 = (PMIB_TCPTABLE_OWNER_PID)malloc(sz4);
        if (pTcp4 && GetExtendedTcpTable(pTcp4, &sz4, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcp4->dwNumEntries; ++i) {
                DWORD pid = pTcp4->table[i].dwOwningPid; if (!pid) continue;
                std::string name, path; if (!GetProcessNameAndPath(pid, name, path)) continue;
                auto& row = map[(int)pid];
                if (row.pid == 0) { row.pid = (int)pid; row.name = name; row.path = path; row.protocol = "TCPv4"; }
                row.localPorts.push_back(std::to_string(ntohs((u_short)pTcp4->table[i].dwLocalPort)));
                row.remotePorts.push_back(std::to_string(ntohs((u_short)pTcp4->table[i].dwRemotePort)));
            }
        }
        if (pTcp4) free(pTcp4);
    }

    // IPv6 TCP
    PMIB_TCP6TABLE_OWNER_PID pTcp6 = nullptr; DWORD sz6 = 0;
    if (GetExtendedTcpTable(NULL, &sz6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcp6 = (PMIB_TCP6TABLE_OWNER_PID)malloc(sz6);
        if (pTcp6 && GetExtendedTcpTable(pTcp6, &sz6, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcp6->dwNumEntries; ++i) {
                DWORD pid = pTcp6->table[i].dwOwningPid; if (!pid) continue;
                std::string name, path; if (!GetProcessNameAndPath(pid, name, path)) continue;
                auto& row = map[(int)pid];
                if (row.pid == 0) { row.pid = (int)pid; row.name = name; row.path = path; row.protocol = "TCPv6"; }
                row.localPorts.push_back(std::to_string(ntohs((u_short)pTcp6->table[i].dwLocalPort)));
                row.remotePorts.push_back(std::to_string(ntohs((u_short)pTcp6->table[i].dwRemotePort)));
            }
        }
        if (pTcp6) free(pTcp6);
    }

    std::vector<NetProcRow> rows;
    rows.reserve(map.size());
    for (auto& kv : map) {
        auto& r = kv.second;
        auto dedup = [](std::vector<std::string>& v){ std::sort(v.begin(), v.end()); v.erase(std::unique(v.begin(), v.end()), v.end()); };
        dedup(r.localPorts);
        dedup(r.remotePorts);
        rows.push_back(r);
    }
    std::sort(rows.begin(), rows.end(), [](const NetProcRow& a, const NetProcRow& b){ return a.pid < b.pid; });
    return rows;
}
