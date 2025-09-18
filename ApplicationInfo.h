#pragma once
#include <string>
#include <vector>

// Unified application information model
struct ApplicationInfo {
    std::wstring name;    // Display name of the app
    std::wstring exePath; // Full path to executable (or install path for UWP)
    std::wstring source;  // "Registry", "UWP", "Filesystem", "Process"
    bool isUWP = false;   // true if UWP app
};
