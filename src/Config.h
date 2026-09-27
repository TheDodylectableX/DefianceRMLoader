// ------------------------------------------------------------------------
// Owns the config struct, INI parser, log file handle, and Log() helper.
// Header-only so both DLLMain.cpp and Hooks.cpp share the same instances.
// ------------------------------------------------------------------------
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <filesystem>
#include <cctype>

namespace fs = std::filesystem;

// -- Configuration Structure ----------------------------------------------------------
struct LoaderConfig {
    bool consoleEnabled = true;
    bool verboseLogging = true;
    bool logAllFiles    = true;
    bool fileLogEnabled = false;
    bool fopenTrace     = false; // Log every fopen call (Very noisy, Use it for debugging only)
};

inline LoaderConfig g_Config;

// -- Log File Handle -------------------------------------------------------------
// Opened in DllMain, Written by Log() in both DLLMain.cpp and Hooks.cpp. Inline so there is exactly one instance across all translation units.
inline FILE* g_LogFile = nullptr;

// -- Log -------------------------------------------------------------
// Writes to the console (If enabled) and to the log file (If enabled).
// The log file is opened with _IONBF (Unbuffered) so every write hits disk immediately and no data is lost on ALT + F4-ing or crashes.
inline void Log(const char* fmt, ...) {
    va_list args;

    if (g_Config.consoleEnabled) {
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }

    if (g_Config.fileLogEnabled && g_LogFile) {
        va_start(args, fmt);
        vfprintf(g_LogFile, fmt, args);
        va_end(args);
    }
}

// -- Log File Open / Close -------------------------------------------------------
inline void OpenLogFile(const fs::path& logPath) {
    fopen_s(&g_LogFile, logPath.string().c_str(), "w");
    if (!g_LogFile) return;
    setvbuf(g_LogFile, nullptr, _IONBF, 0);
}

inline void CloseLogFile() {
    if (g_LogFile) {
        fclose(g_LogFile);
        g_LogFile = nullptr;
    }
}

// -- INI Helpers ---------------------------------------------------------------
namespace detail {
    inline void Trim(std::string& s) {
        const char* ws = " \t\r\n";
        s.erase(0, s.find_first_not_of(ws));
        size_t end = s.find_last_not_of(ws);
        if (end != std::string::npos) s.erase(end + 1);
        else s.clear();
    }

    inline bool ParseBool(const std::string& val, bool defaultVal) {
        if (val == "1" || val == "true" || val == "yes") return true;
        if (val == "0" || val == "false" || val == "no") return false;
        return defaultVal;
    }
}

// -- Write the default INI file ------------------------------------------------------------
inline void WriteDefaultIni(const fs::path& iniPath) {
    FILE* f = nullptr;
    if (fopen_s(&f, iniPath.string().c_str(), "w") != 0 || !f) return;
    fprintf(f,
        "; DefianceRMLoader configuration file. Must be in the same directory as the game executable and the ASI to be read.\n"
        "; All settings are optional, Delete this file to restore defaults.\n"
        "\n"
        "[Console]\n"
        "; Show the mod loader's debug console (0 = Hidden | 1 = Visible)\n"
        "; WARNING: Closing the console will also close the game so be careful!\n"
        "ConsoleEnabled=0\n"
        "\n"
        "[Logging]\n"
        "; Log every asset request including non-modded ones.\n"
        "; Very noisy, Recommended for debugging purposes otherwise disable it for normal play once everything works as it affects the game's file loading speed.\n"
        "VerboseLogging=0\n"
        "\n"
        "; Log [TRACE] lines for assets that have no mod override. "
        "Requires Verbose Logging to be enabled to have any effect.\n"
        "LogAllFiles=0\n"
        "\n"
        "; Mirror all console output to DefianceRMLoader.log in the game folder for debugging purposes. (Doesn't require the console to be enabled) "
        "Doesn't require the console to be enabled.\n"
        "FileLogEnabled=0\n"
        "\n"
        "; Log every internal fopen call. (Very noisy; Only for debugging purposes so it's recommended to keep it off during normal play.) "
        "Keep it off during normal play.\n"
        "FopenTrace=0\n"
    );
    fclose(f);
}

// -- Load Configuration ----------------------------------------------------------------
inline void LoadConfig(const fs::path& iniPath) {
    if (!fs::exists(iniPath)) {
        WriteDefaultIni(iniPath);
        return;
    }

    FILE* f = nullptr;
    if (fopen_s(&f, iniPath.string().c_str(), "r") != 0 || !f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        std::string s(line);
        detail::Trim(s);
        if (s.empty() || s[0] == ';' || s[0] == '#' || s[0] == '[') continue;

        size_t eq = s.find('=');
        if (eq == std::string::npos) continue;

        std::string key = s.substr(0, eq);
        std::string val = s.substr(eq + 1);
        detail::Trim(key);
        detail::Trim(val);

        std::string lkey = key;
        for (char& c : lkey) c = (char)std::tolower((unsigned char)c);

        if      (lkey == "consoleenabled") g_Config.consoleEnabled = detail::ParseBool(val, true);
        else if (lkey == "verboselogging") g_Config.verboseLogging = detail::ParseBool(val, true);
        else if (lkey == "logallfiles")    g_Config.logAllFiles    = detail::ParseBool(val, true);
        else if (lkey == "filelogenabled") g_Config.fileLogEnabled = detail::ParseBool(val, false);
        else if (lkey == "fopentrace")     g_Config.fopenTrace     = detail::ParseBool(val, false);
    }
    fclose(f);
}

// --------------------------------------------------------------------------------------------------------------------
