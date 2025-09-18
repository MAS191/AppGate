// InstalledAppsManager.cpp
// Robust discovery of installed applications across Registry, UWP, Filesystem, and Processes
#include "InstalledAppsManager.h"
#include "ApplicationInfo.h"
#include "Utils.h"
#include <windows.h>
#include <winver.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <psapi.h>
#include <winreg.h>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <cstdio>
#include <fstream>
#pragma comment(lib, "Shlwapi.lib")

namespace fs = std::filesystem;

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    std::wstring w; w.resize(len ? len - 1 : 0);
    if (len > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
    return w;
}

static bool IsExePathW(const std::wstring& p) {
    return PathMatchSpecW(p.c_str(), L"*.exe");
}

static std::wstring NormalizePathW(std::wstring p) {
    if (p.empty()) return p;
    // remove quotes and args first
    PathUnquoteSpacesW(&p[0]);
    PathRemoveArgsW(&p[0]);
    // strip trailing ,<digits> icon index (e.g., ",0")
    size_t comma = p.rfind(L',');
    if (comma != std::wstring::npos) {
        bool digits = true;
        for (size_t i = comma + 1; i < p.size(); ++i) if (!iswdigit(p[i])) { digits = false; break; }
        if (digits) p.erase(comma);
    }
    // expand env
    wchar_t exp[4096]; DWORD n = ExpandEnvironmentStringsW(p.c_str(), exp, _countof(exp));
    const wchar_t* src = (n > 0 && n < _countof(exp)) ? exp : p.c_str();
    // full path
    wchar_t full[4096]; DWORD m = GetFullPathNameW(src, _countof(full), full, nullptr);
    return (m > 0 && m < _countof(full)) ? std::wstring(full) : std::wstring(src);
}

static std::wstring GetFileProductName(const std::wstring& path) {
    DWORD handle = 0; DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (!size) return L"";
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), handle, size, data.data())) return L"";
    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *lpTranslate;
    UINT cbTranslate = 0;
    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) || !cbTranslate) return L"";
    wchar_t subblock[256]; swprintf_s(subblock, L"\\StringFileInfo\\%04x%04x\\ProductName", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
    LPVOID lpBuffer = nullptr; UINT dwBytes = 0;
    if (VerQueryValueW(data.data(), subblock, &lpBuffer, &dwBytes) && dwBytes) { return std::wstring((wchar_t*)lpBuffer); }
    return L"";
}

static std::wstring FindExeInDir(const std::wstring& dir, const std::wstring& preferredName) {
    std::wstring best;
    if (!PathFileExistsW(dir.c_str())) return best;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) continue;
            auto p = entry.path().wstring();
            if (!IsExePathW(p)) continue;
            auto stem = entry.path().stem().wstring();
            if (!preferredName.empty() && _wcsicmp(stem.c_str(), preferredName.c_str()) == 0) {
                return p; // exact match
            }
            if (best.empty()) best = p; // fallback to first .exe
        }
    } catch (...) {}
    return best;
}

void InstalledAppsManager::FromRegistry(std::vector<ApplicationInfo>& out) {
    struct Key { HKEY root; const wchar_t* sub; } keys[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
    };
    for (auto& k : keys) {
        HKEY hKey; if (RegOpenKeyExW(k.root, k.sub, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;
        DWORD idx = 0; wchar_t subName[256]; DWORD subLen;
        while (true) {
            subLen = _countof(subName); FILETIME ft{};
            if (RegEnumKeyExW(hKey, idx++, subName, &subLen, NULL, NULL, NULL, &ft) != ERROR_SUCCESS) break;
            HKEY hApp; if (RegOpenKeyExW(hKey, subName, 0, KEY_READ, &hApp) != ERROR_SUCCESS) continue;
            wchar_t displayName[1024] = L""; DWORD dnSize = sizeof(displayName);
            wchar_t displayIcon[2048] = L""; DWORD diSize = sizeof(displayIcon);
            wchar_t installLocation[2048] = L""; DWORD ilSize = sizeof(installLocation);
            wchar_t uninstallStr[2048] = L""; DWORD usSize = sizeof(uninstallStr);
            RegQueryValueExW(hApp, L"DisplayName", NULL, NULL, (LPBYTE)displayName, &dnSize);
            RegQueryValueExW(hApp, L"DisplayIcon", NULL, NULL, (LPBYTE)displayIcon, &diSize);
            RegQueryValueExW(hApp, L"InstallLocation", NULL, NULL, (LPBYTE)installLocation, &ilSize);
            RegQueryValueExW(hApp, L"UninstallString", NULL, NULL, (LPBYTE)uninstallStr, &usSize);

            std::wstring exeCandidate;
            if (displayIcon[0]) { exeCandidate = NormalizePathW(displayIcon); }
            if (exeCandidate.empty() && uninstallStr[0]) { exeCandidate = NormalizePathW(uninstallStr); }
            if (!exeCandidate.empty() && !IsExePathW(exeCandidate)) exeCandidate.clear();
            if (exeCandidate.empty() && installLocation[0]) {
                std::wstring dir = NormalizePathW(installLocation);
                std::wstring guess;
                if (displayName[0]) guess = dir + L"\\" + displayName + L".exe";
                if (!guess.empty() && PathFileExistsW(guess.c_str())) exeCandidate = guess;
                if (exeCandidate.empty()) exeCandidate = FindExeInDir(dir, displayName);
            }
            if (displayName[0] && !exeCandidate.empty() && PathFileExistsW(exeCandidate.c_str())) {
                out.push_back({displayName, exeCandidate, L"Registry", false});
            }
            RegCloseKey(hApp);
        }
        RegCloseKey(hKey);
    }
}

void InstalledAppsManager::FromUWP(std::vector<ApplicationInfo>& out) {
    // Use a temporary PowerShell script to avoid cmd parsing issues (UTF-16 path safe)
    wchar_t tempPath[MAX_PATH]; GetTempPathW(_countof(tempPath), tempPath);
    wchar_t tmpFile[MAX_PATH]; GetTempFileNameW(tempPath, L"apx", 0, tmpFile);
    std::wstring scriptPath = tmpFile; scriptPath += L".ps1";
    const char* script = "$ErrorActionPreference='SilentlyContinue'; Get-AppxPackage | ForEach-Object { $_.Name + '|' + $_.InstallLocation }\n";
    {
        // Use wide-path ofstream overload on MSVC
        std::ofstream ofs(scriptPath, std::ios::binary);
        ofs.write(script, (std::streamsize)strlen(script));
    }
    std::wstring cmd = L"powershell -NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath + L"\"";
    FILE* pipe = _wpopen(cmd.c_str(), L"rt");
    if (!pipe) { DeleteFileW(scriptPath.c_str()); return; }
    wchar_t wline[4096];
    while (fgetws(wline, _countof(wline), pipe)) {
        std::wstring s(wline);
        while (!s.empty() && (s.back()==L'\r' || s.back()==L'\n')) s.pop_back();
        size_t bar = s.find(L'|'); if (bar == std::wstring::npos) continue;
        std::wstring name = s.substr(0, bar);
        std::wstring loc  = s.substr(bar+1);
        if (!loc.empty() && PathFileExistsW(loc.c_str())) out.push_back({name, loc, L"UWP", true});
    }
    _pclose(pipe);
    DeleteFileW(scriptPath.c_str());
}

void InstalledAppsManager::FromFilesystem(std::vector<ApplicationInfo>& out) {
    std::vector<std::wstring> roots;
    wchar_t pf[MAX_PATH]; if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, pf))) roots.push_back(pf);
    wchar_t pfx86[MAX_PATH]; if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILESX86, NULL, SHGFP_TYPE_CURRENT, pfx86))) roots.push_back(pfx86);
    wchar_t lad[MAX_PATH]; if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, lad))) { roots.push_back(std::wstring(lad) + L"\\Programs"); roots.push_back(lad); }
    wchar_t rad[MAX_PATH]; if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, rad))) roots.push_back(rad);
    for (const auto& root : roots) {
        if (!PathFileExistsW(root.c_str())) continue;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                auto p = entry.path().wstring();
                if (!IsExePathW(p)) continue;
                auto name = GetFileProductName(p);
                if (name.empty()) name = entry.path().stem().wstring();
                out.push_back({name, p, L"Filesystem", false});
            }
        } catch (...) { /* ignore permission errors */ }
    }
}

void InstalledAppsManager::FromProcesses(std::vector<ApplicationInfo>& out) {
    DWORD pids[8192]; DWORD needed = 0;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return;
    DWORD count = needed / sizeof(DWORD);
    for (DWORD i = 0; i < count; ++i) {
        DWORD pid = pids[i]; if (!pid) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) continue;
        wchar_t path[MAX_PATH] = L"";
        if (GetModuleFileNameExW(h, NULL, path, _countof(path))) {
            std::wstring wpath(path);
            std::wstring name = GetFileProductName(wpath);
            if (name.empty()) name = fs::path(wpath).stem().wstring();
            out.push_back({name, wpath, L"Process", false});
        }
        CloseHandle(h);
    }
}

std::vector<ApplicationInfo> InstalledAppsManager::EnumerateAll() {
    std::vector<ApplicationInfo> all;
    FromRegistry(all);
    FromUWP(all);
    FromFilesystem(all);
    FromProcesses(all);

    auto rank = [](const std::wstring& src){
        if (src == L"UWP") return 3; if (src == L"Registry") return 2; if (src == L"Filesystem") return 1; return 0;
    };
    std::sort(all.begin(), all.end(), [&](const ApplicationInfo& a, const ApplicationInfo& b){
        int c = _wcsicmp(a.exePath.c_str(), b.exePath.c_str());
        if (c == 0) return rank(a.source) > rank(b.source);
        return c < 0;
    });
    all.erase(std::unique(all.begin(), all.end(), [](const ApplicationInfo& a, const ApplicationInfo& b){
        return _wcsicmp(a.exePath.c_str(), b.exePath.c_str()) == 0;
    }), all.end());
    return all;
}
