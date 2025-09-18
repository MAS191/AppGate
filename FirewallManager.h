// FirewallManager.h
// AppGate - Manages WFP engine, sublayer, and filter rules
#pragma once
#include <vector>
#include <string>
#include "Models.h"

class FirewallManager {
public:
    FirewallManager();
    ~FirewallManager();
    bool Initialize();
    bool BlockProcessByPID(int pid, const std::string& path);
    bool BlockProcessByPath(const std::string& path);
    // Wide path overloads for Unicode-safe operations
    bool BlockProcessByPathW(const std::wstring& wpath);
    bool UnblockProcessByPID(int pid);
    bool UnblockProcessByPath(const std::string& path);
    bool UnblockProcessByPathW(const std::wstring& wpath);
    std::vector<RuleEntry> ListRules();
    bool DeleteRuleBySerial(int serial);
    void DeleteAllRules();
private:
    void* engineHandle; // FWPM_SESSION0*
    std::vector<RuleEntry> rules;
    bool AddSublayer();
    bool LoadRulesFromWFP();
};
