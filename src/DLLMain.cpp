// -----------------------------------------------------------------------------------------------------------------------------------------------------------
// Entry Point. Also reads configuration INI file before executing the mod loader's logic so that we can take them into account with console and logging etc.
// -----------------------------------------------------------------------------------------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <filesystem>
#include "Config.h"
#include "Hooks.h"

namespace fs = std::filesystem;

// -- Initialization Thread -----------------------------------------------------
static DWORD WINAPI InitThread(LPVOID) {
    Sleep(3000);

    if (HooksInstall()) { Log("[DefianceRMLoader] Ready!\n\n"); }
    else { Log("[DefianceRMLoader] Hook installation failed!\n\n"); }
    return 0;
}

// -- DLLMain -------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_DETACH) { return TRUE; }
    if (reason != DLL_PROCESS_ATTACH) { return TRUE; }

    DisableThreadLibraryCalls(hInst);

    // Step 1: Locate the game's directory and load the configuration INI file
    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(hInst, dllPath, MAX_PATH);
    fs::path gameDir = fs::path(dllPath).parent_path();
    fs::path iniPath = gameDir / L"DefianceRMLoader.ini";

    LoadConfig(iniPath);

    // Step 2: Console -------------------------------------------------------
    if (g_Config.consoleEnabled) {
        AllocConsole();
        FILE* dummy;
        freopen_s(&dummy, "CONOUT$", "w", stdout);
        freopen_s(&dummy, "CONOUT$", "w", stderr);
        freopen_s(&dummy, "CONIN$",  "r", stdin);
        SetConsoleTitleA("DefianceRMLoader - Debug Console");
    }

    // -- Step 3: File Logging --------------------------------------------------
    // Opened with _IONBF (unbuffered) so every write hits the disk immediately.
    // No flush handler needed; Data survives crashes and Alt + F4 attempts.
    if (g_Config.fileLogEnabled) {
        fs::path logPath = gameDir / L"DefianceRMLoader.log";
        OpenLogFile(logPath);
    }

    // -- Step 4: Banner --------------------------------------------------------
    Log("[DefianceRMLoader] Console Initialized.\n");
    Log("[DefianceRMLoader] Build: %s %s\n", __DATE__, __TIME__);
    // Log("[DefianceRMLoader] Config: console=%d verbose=%d logAll=%d fileLog=%d\n", (int)g_Config.consoleEnabled, (int)g_Config.verboseLogging, (int)g_Config.logAllFiles, (int)g_Config.fileLogEnabled);
    Log("[DefianceRMLoader] Initializing Hooks...\n");

    // -- Step 5: Hook Thread ---------------------------------------------------
    CloseHandle(CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr));
    return TRUE;
}
// --------------------------------------------------------------------------------------------------------------------
