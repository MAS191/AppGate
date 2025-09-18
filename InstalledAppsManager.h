#pragma once
#include <vector>
#include <string>
#include "ApplicationInfo.h"

// Aggregates installed applications from multiple sources
class InstalledAppsManager {
public:
    // Enumerate registry (Win32), Start Menu shortcuts, UWP, filesystem, and running processes
    std::vector<ApplicationInfo> EnumerateAll();

private:
    void FromRegistry(std::vector<ApplicationInfo>& out);
    void FromUWP(std::vector<ApplicationInfo>& out); // Uses PackageManager if available, falls back to PowerShell
    void FromFilesystem(std::vector<ApplicationInfo>& out);
    void FromProcesses(std::vector<ApplicationInfo>& out);
};
