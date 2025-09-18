// main.cpp
// Entry point and CLI menu for AppGate
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstddef>
#include <vector>
#include <sstream>
#include "ProcessManager.h"
#include "FirewallManager.h"
#include "Models.h"
#include "Utils.h"
#include "InstalledAppsManager.h"
#include "ApplicationInfo.h"

void PrintBanner();
void PrintMenu();
void ListProcesses(ProcessManager& pm);
void ListInstalledApps(InstalledAppsManager& iam, FirewallManager& fm);
void BlockProcess(FirewallManager& fm, ProcessManager& pm);
void UnblockProcess(FirewallManager& fm, ProcessManager& pm);
void ShowRules(FirewallManager& fm);
void DeleteRuleBySerial(FirewallManager& fm);
void DeleteAllRules(FirewallManager& fm);

static std::string JoinCSV(const std::vector<std::string>& v) {
    std::ostringstream oss; bool first=true; for (auto& s : v){ if(!first) oss<<","; oss<<s; first=false; } return oss.str();
}

int main() {
    PrintBanner();
    ProcessManager processManager;
    InstalledAppsManager iam;
    FirewallManager firewallManager;
    if (!firewallManager.Initialize()) {
        std::cout << "[!] Failed to initialize WFP engine. Run as Administrator.\n";
        return 1;
    }
    int choice = -1;
    while (choice != 0) {
        PrintMenu();
        std::cout << "Enter your choice: ";
        if (!(std::cin >> choice)) { std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); continue; }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        switch (choice) {
            case 1: ListProcesses(processManager); break;
            case 2: ListInstalledApps(iam, firewallManager); break;
            case 3: BlockProcess(firewallManager, processManager); break;
            case 4: UnblockProcess(firewallManager, processManager); break;
            case 5: ShowRules(firewallManager); break;
            case 6: DeleteRuleBySerial(firewallManager); break;
            case 7: DeleteAllRules(firewallManager); break;
            case 0: std::cout << "\nExiting...\n"; break;
            default: std::cout << "Invalid choice. Please try again.\n"; break;
        }
        if (choice != 0) {
            std::cout << "\nPress Enter to continue...";
            std::cin.get();
        }
    }
    return 0;
}

void PrintBanner() {
    std::cout << "\n===================================================\n";
    std::cout << R"(  ___              _____       _       
 / _ \            |  __ \     | |      
/ /_\ \_ __  _ __ | |  \/ __ _| |_ ___ 
|  _  | '_ \| '_ \| | __ / _` | __/ _ \
| | | | |_) | |_) | |_\ \ (_| | ||  __/
\_| |_/ .__/| .__/ \____/\__,_|\__\___|
      | |   | |                        
      |_|   |_|                        )" << "\n";
    std::cout << "                     AppGate\n";
    std::cout << "        Application Network Access Controller\n";
    std::cout << "=====================================================\n";
    std::cout << "  - Block/Unblock processes by PID or Path\n";
    std::cout << "  - List network processes and installed apps\n";
    std::cout << "  - Requires Administrator rights\n";
    std::cout << "=====================================================\n\n";
}

void PrintMenu() {
    std::cout << "\n";
    std::cout << "+--------------------------------------------+\n";
    std::cout << "| 1. List processes using network            |\n";
    std::cout << "| 2. List installed applications             |\n";
    std::cout << "| 3. Block process (by PID or Path)          |\n";
    std::cout << "| 4. Unblock process (by PID or Path)        |\n";
    std::cout << "| 5. Show active rules                       |\n";
    std::cout << "| 6. Delete rule by serial number            |\n";
    std::cout << "| 7. Delete all rules created by this program|\n";
    std::cout << "| 0. Exit                                    |\n";
    std::cout << "+--------------------------------------------+\n";
}

void ListProcesses(ProcessManager& pm) {
    auto rows = pm.ListNetworkProcessesGrouped();
    if (rows.empty()) { std::cout << "[!] No network processes found.\n"; return; }
    std::size_t maxName=4, maxPath=4, maxProto=5, maxL=5, maxR=6;
    for (const auto& r : rows) {
        maxName = std::max(maxName, r.name.size());
        maxPath = std::max(maxPath, r.path.size());
        maxProto= std::max(maxProto, r.protocol.size());
        maxL = std::max(maxL, JoinCSV(r.localPorts).size());
        maxR = std::max(maxR, JoinCSV(r.remotePorts).size());
    }
    std::cout << std::left
        << std::setw(7) << "PID"
        << std::setw((int)maxName+2) << "Name"
        << std::setw((int)maxPath+2) << "Path"
        << std::setw((int)maxProto+2) << "Proto"
        << std::setw((int)maxL+2) << "LocalPorts"
        << std::setw((int)maxR+2) << "RemotePorts" << "\n";
    std::cout << std::string(7+(int)maxName+2+(int)maxPath+2+(int)maxProto+2+(int)maxL+2+(int)maxR+2, '-') << "\n";
    for (const auto& r : rows) {
        std::cout << std::left
            << std::setw(7) << r.pid
            << std::setw((int)maxName+2) << r.name
            << std::setw((int)maxPath+2) << r.path
            << std::setw((int)maxProto+2) << r.protocol
            << std::setw((int)maxL+2) << JoinCSV(r.localPorts)
            << std::setw((int)maxR+2) << JoinCSV(r.remotePorts) << "\n";
    }
}

void ListInstalledApps(InstalledAppsManager& iam, FirewallManager& fm) {
    auto apps = iam.EnumerateAll();
    if (apps.empty()) { std::cout << "[!] No installed applications found.\n"; return; }
    std::size_t maxName = 12, maxPath = 4, maxSrc = 8;
    for (const auto& a : apps) {
        maxName = std::max(maxName, a.name.size());
        maxPath = std::max(maxPath, a.exePath.size());
        maxSrc  = std::max(maxSrc, a.source.size());
    }
    std::cout << std::left
        << std::setw(6) << "#"
        << std::setw((int)maxName+2) << "Application"
        << std::setw((int)maxPath+2) << "Executable Path"
        << std::setw((int)maxSrc+2)  << "Source"
        << std::setw(8) << "UWP" << "\n";
    std::cout << std::string(6+(int)maxName+2+(int)maxPath+2+(int)maxSrc+2+8, '-') << "\n";
    int idx = 1;
    for (const auto& a : apps) {
        std::cout << std::left
            << std::setw(6) << idx
            << std::setw((int)maxName+2) << Utils::WideToUtf8(a.name)
            << std::setw((int)maxPath+2) << Utils::WideToUtf8(a.exePath)
            << std::setw((int)maxSrc+2)  << Utils::WideToUtf8(a.source)
            << std::setw(8) << (a.isUWP ? "Yes" : "No") << "\n";
        ++idx;
    }
    std::cout << "\nEnter number to block (or 'u' to unblock by number, Enter to skip): ";
    std::string input; std::getline(std::cin, input);
    if (input.empty()) return;
    bool unblock = false;
    if (input.size() > 1 && (input[0] == 'u' || input[0] == 'U')) { unblock = true; input = input.substr(1); }
    try {
        int sel = std::stoi(input);
        if (sel < 1 || sel > (int)apps.size()) { std::cout << "[!] Invalid selection.\n"; return; }
        const auto& app = apps[sel-1];
        if (!unblock) fm.BlockProcessByPathW(app.exePath); else fm.UnblockProcessByPathW(app.exePath);
    } catch (...) { std::cout << "[!] Invalid input.\n"; }
}

void BlockProcess(FirewallManager& fm, ProcessManager& pm) {
    std::cout << "Enter PID or process path to block: ";
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) { std::cout << "[!] No input.\n"; return; }
    try {
        int pid = std::stoi(input);
        auto proc = pm.GetProcessByPID(pid);
        if (proc.pid == 0) { std::cout << "[!] PID not found.\n"; return; }
        fm.BlockProcessByPID(proc.pid, proc.path);
    } catch (...) {
        fm.BlockProcessByPath(input);
    }
}

void UnblockProcess(FirewallManager& fm, ProcessManager& pm) {
    std::cout << "Enter PID or process path to unblock: ";
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) { std::cout << "[!] No input.\n"; return; }
    try {
        int pid = std::stoi(input);
        auto proc = pm.GetProcessByPID(pid);
        if (proc.pid == 0) { std::cout << "[!] PID not found.\n"; return; }
        fm.UnblockProcessByPath(proc.path);
    } catch (...) {
        fm.UnblockProcessByPath(input);
    }
}

void ShowRules(FirewallManager& fm) {
    auto rules = fm.ListRules();
    if (rules.empty()) {
        std::cout << "[!] No rules found.\n";
        return;
    }
    std::size_t maxName = 12, maxPath = 4;
    for (const auto& r : rules) {
        maxName = std::max(maxName, static_cast<std::size_t>(r.processName.size()));
        maxPath = std::max(maxPath, static_cast<std::size_t>(r.processPath.size()));
    }
    std::cout << std::left
        << std::setw(5) << "#"
        << std::setw(static_cast<int>(maxName+2)) << "Process Name"
        << std::setw(static_cast<int>(maxPath+2)) << "Path"
        << std::setw(18) << "FilterId" << "\n";
    std::cout << std::string(static_cast<std::size_t>(5+maxName+2+maxPath+2+18), '-') << "\n";
    int idx = 1;
    for (const auto& r : rules) {
        std::cout << std::left
            << std::setw(5) << idx
            << std::setw(static_cast<int>(maxName+2)) << r.processName
            << std::setw(static_cast<int>(maxPath+2)) << r.processPath
            << std::setw(18) << std::to_string(r.filterId) << "\n";
        ++idx;
    }
}

void DeleteRuleBySerial(FirewallManager& fm) {
    auto rules = fm.ListRules();
    if (rules.empty()) {
        std::cout << "[!] No rules to delete.\n";
        return;
    }
    std::cout << "Enter rule serial number to delete: ";
    std::string input;
    std::getline(std::cin, input);
    int serial = 0;
    try { serial = std::stoi(input); } catch (...) { std::cout << "[!] Invalid input.\n"; return; }
    if (!fm.DeleteRuleBySerial(serial)) {
        std::cout << "[!] Rule not found.\n";
    }
}

void DeleteAllRules(FirewallManager& fm) { fm.DeleteAllRules(); }
