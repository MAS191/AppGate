// ProcessManager.h
// Enumerates processes and their network connections
#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include "Models.h"

struct NetProcRow {
    int pid;
    std::string name;
    std::string path;
    std::string protocol; // TCPv4/TCPv6
    std::vector<std::string> localPorts; // as strings
    std::vector<std::string> remotePorts; // as strings
};

class ProcessManager {
public:
    ProcessManager();
    std::vector<ProcessInfo> ListNetworkProcesses(); // legacy flat listing
    std::vector<NetProcRow> ListNetworkProcessesGrouped(); // grouped by PID with CSV ports
    ProcessInfo GetProcessByPID(int pid);
};
