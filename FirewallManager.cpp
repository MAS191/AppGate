// FirewallManager.cpp
// AppGate - Implements WFP engine, sublayer, and filter management
#include "FirewallManager.h"
#include "Utils.h"
#include <windows.h>
#include <fwpmu.h>
#include <vector>
#include <string>
#include <iostream>
#pragma comment(lib, "fwpuclnt.lib")

// Helper: Convert std::string to wide string
static std::wstring s2ws(const std::string& s) {
    int slength = (int)s.length();
    if (slength == 0) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), slength, 0, 0);
    std::wstring r(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), slength, &r[0], len);
    return r;
}

FirewallManager::FirewallManager() : engineHandle(nullptr) {}

FirewallManager::~FirewallManager() {
    if (engineHandle) {
        FwpmEngineClose0((HANDLE)engineHandle);
        engineHandle = nullptr;
    }
}

bool FirewallManager::Initialize() {
    FWPM_SESSION0 session = {0};
    session.displayData.name = const_cast<wchar_t*>(L"AppGate Session");
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, (HANDLE*)&engineHandle) != ERROR_SUCCESS) {
        engineHandle = nullptr;
        return false;
    }
    return AddSublayer();
}

bool FirewallManager::AddSublayer() {
    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.subLayerKey = Utils::GetSublayerGuid();
    sublayer.displayData.name = const_cast<wchar_t*>(L"AppGateSublayer");
    sublayer.displayData.description = const_cast<wchar_t*>(L"Custom sublayer for AppGate");
    sublayer.flags = 0;
    sublayer.weight = 0x100;
    DWORD status = FwpmSubLayerAdd0((HANDLE)engineHandle, &sublayer, NULL);
    return status == ERROR_SUCCESS || status == FWP_E_ALREADY_EXISTS;
}

// Helper to add a filter for a given layer and protocol
static bool AddBlockFilter(HANDLE engineHandle, const std::wstring& wpath, const GUID& subLayer, UINT8 protocol, const GUID& layer, UINT64& outFilterId, const std::string& programName, bool isOutbound) {
    std::wstring ruleName = std::wstring(programName.begin(), programName.end()) + (isOutbound ? L"-Outbound" : L"-Inbound");
    FWPM_FILTER0 filter = {0};
    filter.displayData.name = const_cast<wchar_t*>(ruleName.c_str());
    filter.layerKey = layer;
    filter.subLayerKey = subLayer;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.numFilterConditions = 2;
    filter.filterCondition = new FWPM_FILTER_CONDITION0[2];
    // AppID condition
    FWP_BYTE_BLOB* appIdBlob = nullptr;
    if (FwpmGetAppIdFromFileName0(wpath.c_str(), &appIdBlob) != ERROR_SUCCESS) {
        delete[] filter.filterCondition;
        return false;
    }
    filter.filterCondition[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    filter.filterCondition[0].matchType = FWP_MATCH_EQUAL;
    filter.filterCondition[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    filter.filterCondition[0].conditionValue.byteBlob = appIdBlob;
    // Protocol condition
    filter.filterCondition[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    filter.filterCondition[1].matchType = FWP_MATCH_EQUAL;
    filter.filterCondition[1].conditionValue.type = FWP_UINT8;
    filter.filterCondition[1].conditionValue.uint8 = protocol;
    UINT64 filterId = 0;
    DWORD status = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);
    if (appIdBlob) CoTaskMemFree(appIdBlob);
    delete[] filter.filterCondition;
    if (status == ERROR_SUCCESS) { outFilterId = filterId; return true; }
    return false;
}

bool FirewallManager::BlockProcessByPID(int pid, const std::string& path) {
    return BlockProcessByPath(path);
}

bool FirewallManager::BlockProcessByPath(const std::string& path) {
    if (!engineHandle) return false;
    std::wstring wpath = s2ws(path);
    return BlockProcessByPathW(wpath);
}

bool FirewallManager::BlockProcessByPathW(const std::wstring& wpath) {
    if (!engineHandle) return false;
    const GUID subLayer = Utils::GetSublayerGuid();
    std::string programName;
    // Derive program name from path for rule naming (best-effort)
    {
        std::wstring file = wpath;
        size_t pos = file.find_last_of(L"\\/");
        std::wstring base = (pos != std::wstring::npos) ? file.substr(pos+1) : file;
        programName.assign(base.begin(), base.end());
    }
    struct LayerProto { const GUID* layer; UINT8 proto; bool isOutbound; } layers[] = {
        { &FWPM_LAYER_ALE_AUTH_CONNECT_V4, IPPROTO_TCP, true },
        { &FWPM_LAYER_ALE_AUTH_CONNECT_V4, IPPROTO_UDP, true },
        { &FWPM_LAYER_ALE_AUTH_CONNECT_V6, IPPROTO_TCP, true },
        { &FWPM_LAYER_ALE_AUTH_CONNECT_V6, IPPROTO_UDP, true },
        { &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, IPPROTO_TCP, false },
        { &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, IPPROTO_UDP, false },
        { &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, IPPROTO_TCP, false },
        { &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, IPPROTO_UDP, false },
    };
    bool anySuccess = false;
    for (const auto& lp : layers) {
        UINT64 filterId = 0;
        if (AddBlockFilter((HANDLE)engineHandle, wpath, subLayer, lp.proto, *lp.layer, filterId, programName, lp.isOutbound)) {
            RuleEntry entry;
            entry.serial = (int)rules.size() + 1;
            entry.processName = programName;
            entry.processPath = Utils::WideToUtf8(wpath);
            entry.filterId = filterId;
            rules.push_back(entry);
            anySuccess = true;
        }
    }
    if (anySuccess) {
        std::cout << "[+] Blocked " << programName << " (" << Utils::WideToUtf8(wpath) << ")\n";
    }
    return anySuccess;
}

bool FirewallManager::UnblockProcessByPID(int pid) {
    for (auto it = rules.begin(); it != rules.end(); ) {
        if (it->serial == pid) {
            FwpmFilterDeleteById0((HANDLE)engineHandle, it->filterId);
            std::cout << "[-] Rule removed\n";
            it = rules.erase(it);
        } else {
            ++it;
        }
    }
    return true;
}

bool FirewallManager::UnblockProcessByPath(const std::string& path) {
    for (auto it = rules.begin(); it != rules.end(); ) {
        if (it->processPath == path) {
            FwpmFilterDeleteById0((HANDLE)engineHandle, it->filterId);
            std::cout << "[-] Rule removed\n";
            it = rules.erase(it);
        } else {
            ++it;
        }
    }
    return true;
}

bool FirewallManager::UnblockProcessByPathW(const std::wstring& wpath) {
    return UnblockProcessByPath(Utils::WideToUtf8(wpath));
}

std::vector<RuleEntry> FirewallManager::ListRules() { return rules; }

bool FirewallManager::DeleteRuleBySerial(int serial) {
    for (auto it = rules.begin(); it != rules.end(); ) {
        if (it->serial == serial) {
            FwpmFilterDeleteById0((HANDLE)engineHandle, it->filterId);
            std::cout << "[-] Rule removed\n";
            it = rules.erase(it);
        } else {
            ++it;
        }
    }
    return true;
}

void FirewallManager::DeleteAllRules() {
    for (auto& entry : rules) {
        FwpmFilterDeleteById0((HANDLE)engineHandle, entry.filterId);
    }
    rules.clear();
    std::cout << "[-] All rules removed\n";
}
