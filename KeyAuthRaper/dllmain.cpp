#include <iostream>
#include <vector>
#include <string>

#include "sig_scan.hpp"
#include "minhook/minhook.h"
#include "keyauth_structs.hpp"

void handle_data(api* keyauth_api)
{
    keyauth_api->response.success = true;
    keyauth_api->user_data.username = "page_readwrite";
    keyauth_api->user_data.hwid = "realhwid";
    keyauth_api->user_data.ip = "127.0.0.1"; // ddos me pls

    keyauth_api->user_data.subscriptions; // handle subs

    keyauth_api->user_data.createdate = "never!!!";
}

void (*orig_keyauth_license)(api* keyauth_api, std::string key);
void hk_keyauth_license(api* keyauth_api, std::string key)
{
    handle_data(keyauth_api);
}


void (*orig_keyauth_login)(api* keyauth_api, std::string username, std::string password);
void hk_keyauth_login(api* keyauth_api, std::string username, std::string password)
{
    handle_data(keyauth_api);
}

bool (*orig_check_section_integrity)(const char* section_name, bool fix);
bool hk_check_section_integrity(const char* section_name, bool fix = false)
{
    return false;
}

void run()
{
    auto check_section_integrity = sig_scan::sig_scan("48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 70 ? 0F 29 78", 0);
    if (!check_section_integrity)
    {
        printf("Failed to find check_section_integrity!\n");
        return;
    }

    auto keyauth_license_func = sig_scan::sig_scan("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 B4 24 ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4D 8B F8", 0);
    if (!keyauth_license_func)
    {
        printf("Failed to find the KeyAuth License Function!\n");
        return;
    }

    auto keyauth_login_func = sig_scan::sig_scan("40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 B4 24 ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4D 8B E1 4C 89 4D ? 4D 8B F8 4C 89 45 ? 4C 8B F2 48 89 55 ? 48 8B F1 48 89 4D ? 48 89 95 ? ? ? ? 4C 89 85 ? ? ? ? 4C 89 8D ? ? ? ? 45 33 ED", 0);
    if (!keyauth_login_func)
    {
        printf("Failed to find theKeyAuth Login Function!\n");
        return;
    }

    auto status = MH_Initialize();

    if (status != MH_OK)
    {
        printf("MH_Initialize() failed -> %s\n", MH_StatusToString(status));
        return;
    }

    status = MH_CreateHook((void*)check_section_integrity, (void*)&hk_check_section_integrity, (void**)&orig_check_section_integrity);

    if (status != MH_OK)
    {
        printf("MH_CreateHook() failed -> %s\n", MH_StatusToString(status));
        return;
    }

    status = MH_CreateHook((void*)keyauth_license_func, (void*)&hk_keyauth_license, (void**)&orig_keyauth_license);

    if (status != MH_OK)
    {
        printf("MH_CreateHook() failed -> %s\n", MH_StatusToString(status));
        return;
    }

    status = MH_CreateHook((void*)keyauth_login_func, (void*)&hk_keyauth_login, (void**)&orig_keyauth_login);

    if (status != MH_OK)
    {
        printf("MH_CreateHook() failed -> %s\n", MH_StatusToString(status));
        return;
    }

    status = MH_EnableHook(MH_ALL_HOOKS);

    if (status != MH_OK)
    {
        printf("MH_CreateHook() failed -> %s\n", MH_StatusToString(status));
        return;
    }

    MessageBoxA(0, "Hooked!", "", 0);
}

bool DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    if (ul_reason_for_call != DLL_PROCESS_ATTACH)
        return true;

    AttachConsole(GetCurrentProcessId());

    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)run, 0, 0, 0);

    return true;
}

