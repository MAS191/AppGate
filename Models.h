// Models.h
// Data structures for process and rule info
#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct ProcessInfo {
    int pid = 0;
    std::string name;
    std::string path;
    std::string protocol;
    std::string localAddr;
    std::string remoteAddr;
};

struct RuleEntry {
    int serial = 0;
    std::string processName;
    std::string processPath;
    std::uint64_t filterId = 0; // WFP filter ID
};
