// -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// We implement all MinHook-based function hooks that intercept the game's internal asset loading pipeline and redirect file reads to loosely stored files in the mods directory.
// -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// -- The Game's Asset Pipelines -------------------------------------------------------
// ORIGINAL PIPELINE (Files stored in bigfile.x64.dat) - Handles formats such as: (.x64.DRM | .x64.VRM | .SMF | .MUL | .RAW | .BIN | .CFG | .SCH | etc.)
//   128-slot queue (OriginalSlot array, Resolved at runtime via pattern scan), The original pipeline's read processor function drives the state machine.
//   When state==0 and fileHandle==null; It calls fopen(slot+65, "rb") - The loose-file path we exploit for redirection, Hook_LoadEnqueue resets state=0 and nulls fileHandle after enqueue for any asset with a modded counterpart, Then Hook_FsOpen redirects the fopen call. (Works generically for all folders inside ther archive so no hardcoded prefix matching.)
//
// REMASTER PIPELINE (Files stored in bigfilehd.dat) - Handles formats such as: (.SRM | .DDS | .TRACK | .LIGHT | etc.)
//   Ring buffer (RingSlot array, resolved at runtime via pattern scan; 176 bytes/slot, 1024 slots, index & 0x3FF). The worker thread reads from archive FILE* at slot+24.
//   Hook_RingEnqueue opens the modded asset via g_GameFopen, Swaps slot+24, Zeros offset/size, sSts fcloseFlag=1 (Engine closes handle via g_GameFclose).
//   parityFlag (+336 on HDAssetObj) must be 1; The developers left the loose file path incomplete in the game's code. (Parity=0 causes the processor to discard data.)

// -- Persistence ---------------------------------------------------------------
//   Hook_SkinChange and Hook_CharInit (Both resolved via pattern scan) call InvalidateModdedCacheEntries() before the original to clear stale cache entries (parityFlag=0) while preserving correctly-loaded mod entries (parityFlag=1).
//   Without this; HDResolve returns cached objects and bypasses Hook_RingEnqueue on skin change / level reload.

// -- CRT Boundary Rule ---------------------------------------------------------
//   Game has a statically linked CRT. (All FILE* objects must be opened and closed by the same heap)
//   Use g_GameFopen (Resolved via pattern scan) to open and let the engine close via fcloseFlag=1 + g_GameFclose (Hardcoded RVA; See Patterns::GameFcloseRVA for why fopen could be scanned but fclose couldn't).
//   Never call GameFclose on a handle with fcloseFlag=1; That's a double-free (0xFEFEFEFE heap pattern -> FAST_FAIL_INVALID_ARG crash).

// -- Startup Guard -------------------------------------------------------------
//   g_HooksReady is false until HooksInstall() completes. Hook_FsOpen checks this flag and returns immediately if false. (Preventing crashes when common_fsopen fires during MH_Initialize before g_ModsDir is set up)

// -- Update Resilience ----------------------------------------------------------
//   All hooked functions are located at runtime via byte-pattern signatures (PatternScanner.h) instead of hardcoded RVAs so a game update that merely relocates code (The common case for patches) doesn't break the loader.
//   Five supporting globals (OriginalSlot array, RingSlot array, CacheArr, CacheB listHead, fileCount) aren't functions and can't be scanned directly; They're derived by reading RIP-relative operands at known byte offsets inside functions we've already located (See DataOffsets:: near HooksInstall()).
//   GameFclose (fclose) is the sole exception: It's a statically linked CRT function with a generic prologue shared by sibling file I/O functions and I couldn't find a unique signature so I made it a hardcoded RVA.

// NOTE: The original pipeline is disabled via the "kOriginalPipelineEnabled" flag below hook HookInstall's helper functions due to crashing reasons I didn't look at yet - As for the remaster's pipeline currently it checks for DDS and SRM files as other stuff like LIGHT/TRACK are untested
// -----------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <MinHook.h>
#include <cstdio>
#include <string>
#include <filesystem>
#include <algorithm>
#include <cstdint>
#include "Config.h"
#include "Hooks.h"
#include "PatternScanner.h"

namespace fs = std::filesystem;

// -- Guard Flag ----------------------------------------------------------------
// Is set to true at the end of HooksInstall(); otherwise Hook_FsOpen bails out to prevent crashes when common_fsopen runs during MinHook's initialization/hook creation before g_ModsDir is populated.
// This is to avoid crashing when a user has the mod loader installed but no mods installed therefore it crashes both the loader and the game.
static bool g_HooksReady = false;

// ----------------
// SLOT STRUCTURES
// ----------------
#pragma pack(push, 1)

// Original pipeline load queue slot (200 bytes each, 128 slots).
// Base address resolved at runtime via pattern scan (see DataOffsets::OriginalSlotArrayOffset). Confirmed from LoadEnqueue decompile.
struct OriginalSlot {
    uint8_t  _pad0[40];     // +0   .. +39
    uint64_t fileOffset;    // +40
    uint64_t fileSize;      // +48
    uint8_t  _pad1[4];      // +56  .. +59
    int32_t  state;         // +60 | 0: free | 1: active | 2: waiting | 3: done
    uint8_t  openedByUs;    // +64 | set to 1 by sub_140180BC0 after fopen
    char     filename[135]; // +65 | fopen target we overwrite with mod path
    FILE*    fileHandle;    // +200 null -> triggers fopen(filename)
};

static_assert(offsetof(OriginalSlot, fileOffset)  == 40,  "OriginalSlot::fileOffset");
static_assert(offsetof(OriginalSlot, fileSize)    == 48,  "OriginalSlot::fileSize");
static_assert(offsetof(OriginalSlot, state)       == 60,  "OriginalSlot::state");
static_assert(offsetof(OriginalSlot, openedByUs)  == 64,  "OriginalSlot::openedByUs");
static_assert(offsetof(OriginalSlot, filename)    == 65,  "OriginalSlot::filename");
static_assert(offsetof(OriginalSlot, fileHandle)  == 200, "OriginalSlot::fileHandle");

// HD ring buffer slot (176 bytes each, 1024 slots, index & 0x3FF).
// Base address resolved at runtime via pattern scan (See DataOffsets::RingSlotArrayOffset).
struct RingSlot {
    uint8_t  _pad0[20];      // +0  .. +19
    uint8_t  skipFlag;       // +20
    uint8_t  _pad1[3];       // +21 .. +23
    FILE*    fileHandle;     // *(QWORD*)(v3+3) = +24 | archive FILE* (We swap this one)
    uint8_t  fcloseFlag;     // +32 (1 = Cleanup CB calls fclose)
    uint8_t  _pad2[7];       // +33 .. +39
    uint64_t fileOffset;     // *(QWORD*)(v3+5) = +40 | FileOffset (0 = Read from start)
    uint64_t fileSize;       // *(QWORD*)(v3+6) = +48 | FileSize (0 = Auto-detect)
    void*    callbackFn;     // *(QWORD*)(v3+7) = +56 | Processor callback
    uint8_t  _pad3[16];      // +64 .. +79
    int64_t  assetObjPtr;    // *(QWORD*)(v3+10) = +80
    int64_t  readBufPtr;     // *(QWORD*)(v3+11) = +88
    uint8_t  _pad4[8];       // +96 .. +103
    uint8_t  completionFlag; // +104
    char     nameString[71]; // +105 .. +175
};

static_assert(offsetof(RingSlot, skipFlag)       == 20,  "RingSlot::skipFlag");
static_assert(offsetof(RingSlot, fileHandle)     == 24,  "RingSlot::fileHandle");
static_assert(offsetof(RingSlot, fcloseFlag)     == 32,  "RingSlot::fcloseFlag");
static_assert(offsetof(RingSlot, fileOffset)     == 40,  "RingSlot::fileOffset");
static_assert(offsetof(RingSlot, fileSize)       == 48,  "RingSlot::fileSize");
static_assert(offsetof(RingSlot, callbackFn)     == 56,  "RingSlot::callbackFn");
static_assert(offsetof(RingSlot, assetObjPtr)    == 80,  "RingSlot::assetObjPtr");
static_assert(offsetof(RingSlot, readBufPtr)     == 88,  "RingSlot::readBufPtr");
static_assert(offsetof(RingSlot, completionFlag) == 104, "RingSlot::completionFlag");
static_assert(offsetof(RingSlot, nameString)     == 105, "RingSlot::nameString");
static_assert(sizeof(RingSlot)                   == 176, "RingSlot size");

// HD asset object - Partial layout; Only fields we access.
// NOTE: name was originally mapped at +64 (immediately after nextPtr) but HDResolve's decompile (sub_1400FA530) proves the engine writes and compares the name string at +68
// Example: "v35[v28 + 68 - FileName] = *v35;" when populating a fresh cache entry and "v31 = j + 68" during Cache B lookup.
// There's a 4-byte field between nextPtr and name that was never mapped; No idea what it contains so I left it as padding.
// parityFlag stays pinned at it’s debugger-confirmed absolute offset (+336).
struct HDAssetObj {
    int32_t  assetType;      // +0 | 0: DDS | 1: SRM | 3: X64.DRM | 2: LIGHT
    int32_t  seqLoadId;      // +4
    int32_t  crc32Hash;      // +8
    int32_t  hashIndex;      // +12
    int32_t  refCount;       // +16
    int32_t  stateFlag;      // +20
    int32_t  ringDispatchId; // +24
    uint8_t  _pad0[28];      // +28 .. +55
    int64_t  nextPtr;        // +56 .. +63
    uint8_t  _pad0b[4];      // +64 .. +67 | unmapped field; name doesn't start here
    char     name[264];      // +68  .. +331
    uint8_t  readinessFlag;  // +332 | Don't set it manually; Race with main thread
    uint8_t  _pad1[3];       // +333 .. +335
    uint8_t  parityFlag;     // +336 | 0: loose (discards) | 1: archive (accepted)
};

static_assert(offsetof(HDAssetObj, seqLoadId)     == 4,   "HDAssetObj::seqLoadId");
static_assert(offsetof(HDAssetObj, crc32Hash)     == 8,   "HDAssetObj::crc32Hash");
static_assert(offsetof(HDAssetObj, hashIndex)     == 12,  "HDAssetObj::hashIndex");
static_assert(offsetof(HDAssetObj, nextPtr)       == 56,  "HDAssetObj::nextPtr");
static_assert(offsetof(HDAssetObj, name)          == 68,  "HDAssetObj::name");
static_assert(offsetof(HDAssetObj, readinessFlag) == 332, "HDAssetObj::readinessFlag");
static_assert(offsetof(HDAssetObj, parityFlag)    == 336, "HDAssetObj::parityFlag");

#pragma pack(pop)

// -- Globals -------------------------------------------------------------------
static fs::path g_GameDir;
static fs::path g_ModsDir;

// -- Resolved Data Addresses ---------------------------------------------------
// Populated once in HooksInstall() by reading RIP-relative operands out of already pattern-scanned functions.
// Zero until resolved; Every access site below guards against that rather than dereferencing a null/garbage pointer.
static uintptr_t g_OriginalSlotArrayAddress = 0;
static uintptr_t g_RingSlotArrayAddress     = 0;
static uintptr_t g_CacheArrAddress          = 0;
static uintptr_t g_CacheBListHeadAddress    = 0;
static uintptr_t g_FileCountAddress         = 0;

// -- CRC-32/MPEG-2 -------------------------------------------------------------
static uint32_t LOK_CRC32(const std::string& input) {
    std::string s = input;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    uint32_t crc = 0xFFFFFFFF;
    for (unsigned char byte : s) {
        crc ^= (uint32_t)byte << 24;
        for (int bit = 0; bit < 8; ++bit) crc = (crc & 0x80000000) ? (crc << 1) ^ 0x04C11DB7 : (crc << 1);
    }
    return ~crc;
}

// -- Path Utilities ------------------------------------------------------------
static std::string NormalizePath(const std::string& path) {
    std::string s = path;
    std::replace(s.begin(), s.end(), '\\', '/');
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}

static std::string WideToUTF8(const std::wstring& w) {
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), len, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

static fs::path FindModFile(const char* gameRelativePath) {
    if (!gameRelativePath || !*gameRelativePath) return {};
    const char* p = gameRelativePath;
    if (p[0] == '/' || p[0] == '\\') return {};
    if (p[0] != '\0' && p[1] == ':') return {};
    std::string normalized = NormalizePath(std::string(gameRelativePath));
    fs::path candidate = g_ModsDir / normalized;
    if (fs::exists(candidate)) return candidate;
    return {};
}

static void LogModLoad(const char* tag, const std::string& relKey, const fs::path& modPath) {
    std::error_code ec;
    uintmax_t size = fs::file_size(modPath, ec);
    uint32_t  hash = LOK_CRC32(relKey);
    Log("[%s] %-45s | size: %7llu bytes | crc32: 0x%08X\n", tag, relKey.c_str(), (unsigned long long)(ec ? 0 : size), hash);
}

// -- Safe Memory Helpers -------------------------------------------------------
// ALL __try blocks must live in plain-C helper functions (MSVC C2712).

static bool TryGetAssetName(const HDAssetObj* obj, char* outBuf, size_t bufSize) {
    __try {
        if (!obj || !obj->name[0]) return false;
        strncpy_s(outBuf, bufSize, obj->name, _TRUNCATE);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool TrySetParityFlag(HDAssetObj* obj) {
    __try {
        obj->parityFlag = 1;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static uint8_t TryReadParityFlag(const HDAssetObj* obj) {
    __try { return obj->parityFlag; } __except(EXCEPTION_EXECUTE_HANDLER) { return 0xFF; }
}

// Used only where the object pointer's validity isn't already established by the engine handing it to us live (example: raw cache-array/linked-list scans in InvalidateModdedCacheEntries)
// RingEnqueue/ModelProcessor/TextureProcessor read assetType directly since their object pointers come straight from an active engine callback and are already trusted elsewhere in those hooks.
static int32_t TryReadAssetType(const HDAssetObj* obj) {
    __try { return obj->assetType; } __except(EXCEPTION_EXECUTE_HANDLER) { return -1; }
}

static __int64 TryReadOutputStructPtr(__int64 outputStruct) {
    __try { return *reinterpret_cast<__int64*>(outputStruct); } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static uint32_t TryReadOutputStructSeqId(__int64 outputStruct) {
    __try { return *reinterpret_cast<uint32_t*>(outputStruct + 8); } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static uint32_t TryReadFileMagic(__int64 fileBuffer) {
    __try { return *reinterpret_cast<uint32_t*>(fileBuffer); } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// TrySwapRingSlotFile: Swaps the ring slot's FILE* to our mod file.
// actualFileSize must be the real size of the mod file in bytes; We mustn't zero slot->fileSize because the buffer allocator (sub_1400F0310) uses it to set up the memory pool before fread.
// Passing 0 causes it to receive the sentinel value 0x1 as its block pointer then dereference 0x1+0x20=0x21; That's the NULL_CLASS_PTR_READ crash seen with .light and other files.
// fileOffset is zeroed because loose files start at byte 0 (Not an archive offset obviously).
static FILE* TrySwapRingSlotFile(RingSlot* slot, FILE* newFile, uint64_t actualFileSize) {
    __try {
        FILE* orig       = slot->fileHandle;
        slot->fileHandle = newFile;
        slot->fileOffset = 0;              // Loose File: Read from start
        slot->fileSize   = actualFileSize; // Must be real size; 0 breaks allocator
        slot->fcloseFlag = 1;              // Engine cleanup calls g_GameFclose on our handle
        return orig;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// Safely read the next pointer from a Cache B node (node+56).
static __int64* TryReadCacheBNext(const __int64* node) {
    __try { return reinterpret_cast<__int64*>(*reinterpret_cast<const __int64*>(reinterpret_cast<const char*>(node) + 56)); } __except(EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// Safely unlink a Cache B node by writing next ptr into prev's next field.
static void TryUnlinkCacheBNode(__int64* prev, __int64* next, uintptr_t nextOffset) {
    __try { *reinterpret_cast<__int64**>(reinterpret_cast<char*>(prev) + nextOffset) = next; } __except(EXCEPTION_EXECUTE_HANDLER) {}
}

// -- Game fopen/fclose ---------------------------------------------------------
// g_GameFopen is resolved via byte-pattern scan in HooksInstall() (the "fopen" CRT stub jumping into common_fsopen).
// g_GameFclose has no reliable unique signature and is pinned to a hardcoded RVA instead. See Patterns::GameFcloseRVA below.
typedef FILE*(__cdecl* PFN_GameFopen) (const char* path, const char* mode);
typedef int  (__cdecl* PFN_GameFclose)(FILE* stream);
static  PFN_GameFopen  g_GameFopen  = nullptr;
static  PFN_GameFclose g_GameFclose = nullptr;

// GameFclose: Only call this for FILE* handles that aren't tracked by the engine's cleanup callback (example: fcloseFlag=0 handles).
// With fcloseFlag=1 the engine calls g_GameFclose via its cleanup callback automatically; Calling this separately would double-close and corrupt the heap.
static void GameFclose(FILE* fp) { if (fp && g_GameFclose) g_GameFclose(fp); }

// -- HD Swap Table -------------------------------------------------------------
static CRITICAL_SECTION g_SwapLock;
struct SwapEntry { __int64 assetObjPtr; FILE* fp; };
static SwapEntry g_SwapTable[64];
static int       g_SwapCount = 0;

static void RegisterSwap(__int64 assetObjPtr, FILE* fp) {
    // NOTE: with fcloseFlag=1 the engine's cleanup callback owns the FILE* lifecycle and calls g_GameFclose automatically.
    // We mustn't call GameFclose here because that would double-close the handle and corrupt the heap (Use-after-free → 0xFEFEFEFE → FAST_FAIL_INVALID_ARG crash).
    // The swap table is now diagnostic-only: we track asset ptrs but don't manage FILE* lifetimes ourselves.
    EnterCriticalSection(&g_SwapLock);
    for (int i = 0; i < g_SwapCount; ++i) {
        if (g_SwapTable[i].assetObjPtr == assetObjPtr) {
            g_SwapTable[i].fp = fp; // Update pointer for diagnostics only, No close.
            LeaveCriticalSection(&g_SwapLock);
            return;
        }
    }
    if (g_SwapCount < 64) g_SwapTable[g_SwapCount++] = { assetObjPtr, fp };
    LeaveCriticalSection(&g_SwapLock);
}

static void RemoveSwap(__int64 assetObjPtr) {
    EnterCriticalSection(&g_SwapLock);
    for (int i = 0; i < g_SwapCount; ++i) {
        if (g_SwapTable[i].assetObjPtr == assetObjPtr) {
            g_SwapTable[i] = g_SwapTable[--g_SwapCount];
            break;
        }
    }
    LeaveCriticalSection(&g_SwapLock);
}

// -- Cache A Invalidation ------------------------------------------------------
// Clears Cache A entries for modded assets so that the next HDResolve call does a fresh lookup that goes all the way through to the ring buffer.
// Without this, Skin changes and level reloads return the cached asset object and skip Hook_RingEnqueue entirely; Mods stop applying after first load.
static void InvalidateModdedCacheEntries() {
    // Strategy: Only invalidate cache entries for modded assets that have parityFlag=0 (Loaded from archive and not from our mod file).
    // If an asset already has parityFlag=1 it was loaded from our mod and is correct so we leave it alone.
    // This prevents the skin change menu from repeatedly clearing correctly-loaded mod assets and falling back to archive data.
    // We also re-ensure parityFlag=1 on any cached mod asset that has it set already, so it survives any engine attempts to reset it.

    // Addresses failed to resolve at startup; HooksInstall() already logged this. Skip silently rather than dereferencing a null or garbage pointer on every skin change / level load.
    if (!g_CacheArrAddress || !g_CacheBListHeadAddress || !g_FileCountAddress) { return; }

    int       fileCount = *reinterpret_cast<int*>(g_FileCountAddress);
    uint64_t* cacheArr  = *reinterpret_cast<uint64_t**>(g_CacheArrAddress);
    int cleared         = 0;
    int reinforced      = 0;

    // -- Cache A ---------------------------------------------------------------
    if (cacheArr && fileCount > 0 && fileCount <= 100000) {
        for (int i = 0; i < fileCount; i++) {
            __int64 obj = (__int64)cacheArr[i];
            if (!obj || obj < 0x10000 || obj > 0x7FFFFFFFFFFF) continue;

            auto* assetObj = reinterpret_cast<HDAssetObj*>(obj);

            // DDS/SRM only for this release; See the Release Scope note at the top of the file. -1 (unreadable) is skipped along with it.
            int32_t assetType = TryReadAssetType(assetObj);
            if (assetType != 0 && assetType != 1) continue;

            char name[sizeof(HDAssetObj::name)] = {};
            if (!TryGetAssetName(assetObj, name, sizeof(name))) continue;
            if (FindModFile(name).empty()) continue;

            uint8_t parity = TryReadParityFlag(assetObj);
            if (parity == 1) { reinforced++; } // Already loaded from mod; Leave the cache intact, Just reinforce.
            else { // Loaded from archive (parity=0); Clear so next resolve goes through ring buffer and gets our modded file.
                cacheArr[i] = 0;
                cleared++;
            }
        }
    }
    // -- Cache B ---------------------------------------------------------------
    auto** listHead = reinterpret_cast<__int64**>(g_CacheBListHeadAddress); {
        __int64* prev = nullptr;
        __int64* curr = *listHead;
        while (curr) {
            __int64* next = TryReadCacheBNext(curr);
            if (!next && curr != *listHead) break;

            char name[sizeof(HDAssetObj::name)] = {};
            auto* assetObj = reinterpret_cast<HDAssetObj*>(curr);

            // DDS/SRM only for this release; Same scope limit as Cache A above.
            int32_t assetType = TryReadAssetType(assetObj);
            bool typeSupported = (assetType == 0 || assetType == 1);

            if (typeSupported
                && TryGetAssetName(assetObj, name, sizeof(name))
                && !FindModFile(name).empty()) {
                uint8_t parity = TryReadParityFlag(assetObj);
                if (parity == 0) { // Loaded from archive; Unlink from Cache B
                    if (prev) TryUnlinkCacheBNode(prev, next, 56);
                    else *listHead = next;
                    if (cacheArr && fileCount > 0) {
                        int hashIdx = assetObj->hashIndex;
                        if (hashIdx >= 0 && hashIdx < fileCount) cacheArr[hashIdx] = 0;
                    }
                    cleared++;
                    curr = next;
                    continue;
                } else { reinforced++; }
            }
            prev = curr;
            curr = next;
        }
    }
    if ((cleared > 0 || reinforced > 0) && g_Config.verboseLogging) Log("[MOD] Cache: Cleared %d stale and kept %d valid mod entries\n", cleared, reinforced);
}

// -- Trampoline typedefs -------------------------------------------------------
typedef __int64(__fastcall* PFN_LoadEnqueue)(const char* a1, char a2, __int64 a3, __int64 a4, __int64 a5, uint64_t* a6, int a7, __int64 a8, __int64 a9, __int64 a10, int a11);
typedef char(__fastcall* PFN_OrigReadProcessor)(__int64 a1, __int64 a2, __int64 a3); // Original pipeline read processor state machine.
typedef __int64(__fastcall* PFN_HDResolve)(__int64 outputStruct, char* baseName, int assetType);
typedef __int64(__fastcall* PFN_ModelProcessor)(__int64 fileBuffer, __int64 a2, int* assetObj);
typedef __int64(__fastcall* PFN_TextureProcessor)(__int64 fileBuffer, __int64 a2, int* assetObj);
typedef __int64(__fastcall* PFN_RingEnqueue)(__int64 a1);
typedef __int64(__fastcall* PFN_FsOpen)(char* FileName, void* Mode);
typedef __int64(__fastcall* PFN_SkinChange)(__int64 a1, __int64 a2);                 // Skin Change / Hot Reload. Zeros scene graph and calls char loader.
typedef __int64(__fastcall* PFN_CharInit)(__int64 a1, __int64 a2, __int64 a3);       // Character Initialization. Called on first load and level reload.
typedef HANDLE(WINAPI* PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* PFN_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

static PFN_LoadEnqueue       g_OrigLoadEnqueue       = nullptr;
static PFN_OrigReadProcessor g_OrigOrigReadProcessor = nullptr;
static PFN_HDResolve         g_OrigHDResolve         = nullptr;
static PFN_ModelProcessor    g_OrigModelProcessor    = nullptr;
static PFN_TextureProcessor  g_OrigTextureProcessor  = nullptr;
static PFN_RingEnqueue       g_OrigRingEnqueue       = nullptr;
static PFN_FsOpen            g_OrigFsOpen            = nullptr;
static PFN_SkinChange        g_OrigSkinChange        = nullptr;
static PFN_CharInit          g_OrigCharInit          = nullptr;
static PFN_CreateFileW       g_OrigCreateFileW       = nullptr;
static PFN_CreateFileA       g_OrigCreateFileA       = nullptr;

// -- Hook: CreateFileW/A (diagnostic) -----------------------------------------
static HANDLE WINAPI Hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurity, DWORD dwCreation, DWORD dwFlags, HANDLE hTemplate) {
    if (lpFileName && g_Config.verboseLogging) {
        std::string narrow = WideToUTF8(std::wstring(lpFileName));
        if (NormalizePath(narrow).find("legacy of kain") != std::string::npos) Log("[CREATEFILE-W] \"%s\"\n", narrow.c_str());
    }
    return g_OrigCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurity, dwCreation, dwFlags, hTemplate);
}

static HANDLE WINAPI Hook_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurity, DWORD dwCreation,
    DWORD dwFlags, HANDLE hTemplate) {
    if (lpFileName && g_Config.verboseLogging) { if (NormalizePath(std::string(lpFileName)).find("legacy of kain") != std::string::npos) Log("[CREATEFILE-A] \"%s\"\n", lpFileName); }
    return g_OrigCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurity, dwCreation, dwFlags, hTemplate);
}

// -- Hook: sub_1400839D0 (Original Pipeline Enqueuer) -------------------------
//   The engine writes the archive FILE* handle into the slot during enqueue.
//   The original pipeline's read processor only calls fopen(slot+65) when slot+200 (fileHandle) is null.
//   Hook_FsOpen already intercepts that fopen and redirects to the mods folder so if a mod exists for this asset then
//   We intercept BEFORE the original enqueuer runs and temporarily patch the slot array so the slot that's about to be allocated starts with fileHandle=null.
//   The original enqueuer then writes a null handle and the read processor takes the fopen branch.

//   Since we don't know which slot will be allocated, We instead store the filename and intercept the fopen in Hook_FsOpen which already works.
//   The only change needed is to ensure the read processor sees fileHandle=null.

//   From the decompiled function: The enqueuer allocates a slot from the 128-slot array and writes the archive FILE* into slot+200.
//   We scan for the freshly allocated slot AFTER the call (state will be 1, filename matches) and null slot+200 immediately.
//   The read processor runs later and sees null - fopen. Hook_FsOpen redirects the fopen to our mod file. Clean, no mid-read nulling.
static __int64 __fastcall Hook_LoadEnqueue(const char* a1, char a2, __int64 a3, __int64 a4, __int64 a5, uint64_t* a6, int a7, __int64 a8, __int64 a9, __int64 a10, int a11) {
    if (a1 && *a1 && g_Config.verboseLogging && g_Config.logAllFiles) Log("[TRACE] LoadEnqueue: \"%s\"\n", a1);

    __int64 result = g_OrigLoadEnqueue(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);

    if (!a1 || !*a1) return result;

    // Only bother scanning if a mod exists for this file
    fs::path modFile = FindModFile(a1);
    if (modFile.empty()) return result;

    if (!g_OriginalSlotArrayAddress) return result; // Address failed to resolve at startup

    // Scan slots for the one just allocated (state==1, filename matches a1)
    auto* slots = reinterpret_cast<OriginalSlot*>(g_OriginalSlotArrayAddress);

    for (int i = 0; i < 128; i++) {
        OriginalSlot& slot = slots[i];
        if (slot.state != 1) continue;
        if (_stricmp(slot.filename, a1) != 0) continue;

        // Found it. To force the fopen path in the read processor we need: state == 0 (the fopen branch checks !state) | fileHandle == null (Or else it takes the archive read path)
        // Reset both. The read processor will then call fopen(slot.filename), Hook_FsOpen redirects to our mod file, engine manages the rest.
        slot.fileHandle = nullptr;
        slot.state      = 0;
        LogModLoad("MOD ORIG", NormalizePath(std::string(a1)), modFile);
        Log("[MOD] ORIG slot %d reset for fopen redirect: \"%s\"\n", i, a1);
        break;
    }
    return result;
}

// -- Hook: sub_140180BC0 (Original Pipeline Read Processor) -------------------
// Passthrough only. File redirection is handled entirely by Hook_LoadEnqueue (Nulls the archive handle at allocation time) and Hook_FsOpen (redirects the resulting fopen call to the mod file).
// No slot modification here; Modifying the slot mid-read caused FAST_FAIL_INVALID_ARG crashes because the state==1 read path tries to use slot->fileHandle immediately.
static char __fastcall Hook_OrigReadProcessor(__int64 a1, __int64 a2, __int64 a3) { return g_OrigOrigReadProcessor(a1, a2, a3); }

// -- Hook: sub_1400F0600 (HD ring buffer enqueuer) -----------------------------
static __int64 __fastcall Hook_RingEnqueue(__int64 a1) {
    __int64 result = g_OrigRingEnqueue(a1);

    if (!g_RingSlotArrayAddress) return result; // Address failed to resolve at startup

    uint32_t  slotIdx = ((uint32_t)result - 1) & 0x3FF;
    auto*     slot    = reinterpret_cast<RingSlot*>(g_RingSlotArrayAddress + sizeof(RingSlot) * slotIdx);

    auto* assetObj    = reinterpret_cast<HDAssetObj*>(slot->assetObjPtr);
    if (!assetObj) return result;

    // DDS (0) | SRM (1) only for this release; Every other HD asset type (.track, .light, HD .drm, etc.) is left completely untouched. See the Release Scope at the top of the file.
    // assetObj here comes from an active engine callback (Already trusted elsewhere in this hook) so a direct read is consistent with Hook_ModelProcessor/TextureProcessor.
    if (assetObj->assetType != 0 && assetObj->assetType != 1) return result;

    char assetName[sizeof(HDAssetObj::name)] = {};
    if (!TryGetAssetName(assetObj, assetName, sizeof(assetName))) return result;

    fs::path modFile = FindModFile(assetName);
    if (modFile.empty()) {
        if (g_Config.verboseLogging && g_Config.logAllFiles) Log("[TRACE HD ENQUEUE] \"%s\"\n", assetName);
        return result;
    }

    if (!g_GameFopen) {
        Log("[MOD] g_GameFopen not set; Cannot redirect \"%s\"\n", assetName);
        return result;
    }

    std::string modPathStr = modFile.string();
    LogModLoad("MOD HD", NormalizePath(std::string(assetName)), modFile);

    // Get actual file size before opening: fs::file_size uses Win32 directly, No CRT involvement, Safe to call here.
    // This is passed to TrySwapRingSlotFile so the buffer allocator (sub_1400F0310) receives the correct size and can set up its memory pool.
    // Zeroing fileSize caused a NULL_CLASS_PTR_READ crash for large assets like .light files whose allocator takes a different code path.
    std::error_code fsec;
    uint64_t actualSize = (uint64_t)fs::file_size(modFile, fsec);
    if (fsec || actualSize == 0) {
        Log("[MOD] Cannot determine file size for: \"%s\"\n", modPathStr.c_str());
        return result;
    }

    FILE* modFp = g_GameFopen(modPathStr.c_str(), "rb");
    if (!modFp) {
        Log("[MOD] Failed to open: \"%s\"\n", modPathStr.c_str());
        return result;
    }

    FILE* origFp = TrySwapRingSlotFile(slot, modFp, actualSize);
    if (!origFp) { // Swap failed; Engine never received this handle so we close it. Use GameFclose to match the CRT that opened it (g_GameFopen).
        GameFclose(modFp);
        Log("[MOD] Slot swap failed for: \"%s\"\n", assetName);
        return result;
    }

    // Set parityFlag before worker wakes; Should cover all asset types.
    TrySetParityFlag(assetObj);
    Log("[MOD] HD Slot %u | Swapped: \"%s\" -> \"%s\"\n", slotIdx, assetName, modPathStr.c_str());
    RegisterSwap((__int64)assetObj, modFp);
    return result;
}

// -- Hook: common_fsopen<char> (Address resolved via pattern scan) -----------
// Intercepts all internal fopen calls.
// For the remastered pipeline: Never fires (Worker reads from archive FILE* directly).
// For the original pipeline: Fires when Hook_OrigReadProcessor nulls the archive handle causing the engine to call fopen(slot->filename).
// We redirect the path to our mod file. Engine manages the FILE* lifecycle. All paths through here log when verbose so we can diagnose redirects.
static thread_local char t_FsOpenRedirect[MAX_PATH * 2];

static __int64 __fastcall Hook_FsOpen(char* FileName, void* Mode) {
    if (!g_HooksReady) return g_OrigFsOpen(FileName, Mode);
    if (!FileName || !*FileName) return g_OrigFsOpen(FileName, Mode);

    // Diagnostic: Log every fopen call. Gated behind FopenTrace=1 in INI because it fires for every save file, config file, etc. (Very noisy.)
    if (g_Config.fopenTrace) Log("[FOPEN TRACE] \"%s\"\n", FileName);

    fs::path modFile = FindModFile(FileName);
    if (modFile.empty()) return g_OrigFsOpen(FileName, Mode);

    std::string modPathStr = modFile.string();
    if (modPathStr.size() >= sizeof(t_FsOpenRedirect) - 1) {
        Log("[MOD] FsOpen path too long (%zu): \"%s\"\n", modPathStr.size(), modPathStr.c_str());
        return g_OrigFsOpen(FileName, Mode);
    }

    memcpy(t_FsOpenRedirect, modPathStr.c_str(), modPathStr.size() + 1);
    LogModLoad("MOD FOPEN", NormalizePath(std::string(FileName)), modFile);
    Log("[MOD] FsOpen: \"%s\" -> \"%s\"\n", FileName, t_FsOpenRedirect);
    return g_OrigFsOpen(t_FsOpenRedirect, Mode);
}

// -- Hook: sub_1400F8090 (HD Asset Resolver) -----------------------------------
// Pure passthrough and diagnostics only, No cache clearing.
static __int64 __fastcall Hook_HDResolve(
    __int64 outputStruct, char* baseName, int assetType) {
    __int64 result = g_OrigHDResolve(outputStruct, baseName, assetType);

    if (!g_Config.verboseLogging || !baseName || !*baseName) return result;

    // DDS/SRM only for this release (See "Release Scope" note at the top of the file)
    // assetType 2 is LIGHT and type 3 (.X64.DRM) is a real engine recognized type but Hook_RingEnqueue no longer acts on it
    // So we don't report a "hit" here either because doing so would falsely imply a replacement that won't actually happen.
    static const char* extensions[] = { ".dds", ".srm", nullptr, nullptr };
    const char* ext = (assetType >= 0 && assetType <= 3) ? extensions[assetType] : nullptr;
    if (!ext) {
        if (g_Config.logAllFiles) Log("[TRACE HD] HDResolve: \"%s\" | Unhandled assetType: %d\n", baseName, assetType);
        return result;
    }

    std::string fullRelKey = NormalizePath(std::string(baseName)) + ext;

    if (!FindModFile(fullRelKey.c_str()).empty()) {
        __int64  assetPtr = TryReadOutputStructPtr(outputStruct);
        uint32_t seqId    = TryReadOutputStructSeqId(outputStruct);
        Log("[MOD] HDResolve hit: \"%s\" | Asset Pointer: 0x%llX | seqID: %u\n",
            fullRelKey.c_str(), (unsigned long long)assetPtr, seqId);
        if (assetPtr) {
            auto* obj = reinterpret_cast<HDAssetObj*>(assetPtr);
            char  name[sizeof(HDAssetObj::name)] = {};
            TryGetAssetName(obj, name, sizeof(name));
            uint8_t parity = TryReadParityFlag(obj);
            Log("[MOD] assetObj Name: \"%s\" | Parity: %d\n", name, (int)parity);
        }
    }
    else if (g_Config.logAllFiles) { Log("[TRACE HD] HDResolve: \"%s\" | Type: %d\n", baseName, assetType); }
    return result;
}

// -- Hook: sub_1400F7C10 (HD Model Processor) ---------------------------
static __int64 __fastcall Hook_ModelProcessor(
    __int64 fileBuffer, __int64 a2, int* assetObjRaw) {
    if (assetObjRaw) {
        auto*   obj    = reinterpret_cast<HDAssetObj*>(assetObjRaw);
        uint8_t parity = TryReadParityFlag(obj);
        bool isGeometry = (obj->assetType == 1); // SRM Only

        if (parity == 0 && isGeometry) {
            char name[sizeof(HDAssetObj::name)] = {};
            TryGetAssetName(obj, name, sizeof(name));
            if (name[0] != '\0') {
                fs::path modFile = FindModFile(name);
                if (!modFile.empty()) {
                    if (TrySetParityFlag(obj)) {
                        Log("[MOD] parityFlag set for: %s\n", name);
                        if (fileBuffer) {
                            uint32_t magic = TryReadFileMagic(fileBuffer);
                            // Log("[MOD] File Magic: 0x%08X (SRM=0x084D5253 | DDS=0x20534444)\n", magic);
                        }
                    }
                    RemoveSwap((__int64)obj);
                }
            }
        }

        if (g_Config.verboseLogging) {
            char name[sizeof(HDAssetObj::name)] = {};
            if (TryGetAssetName(obj, name, sizeof(name)))
                if (strstr(name, ".srm")) Log("[PROCESSOR] \"%s\" | Parity: %d\n", name, (int)parity);
        }
    }
    return g_OrigModelProcessor(fileBuffer, a2, assetObjRaw);
}

// -- Hook: sub_1400F79E0 (HD Texture Processor) --------------------------------
static __int64 __fastcall Hook_TextureProcessor(
    __int64 fileBuffer, __int64 a2, int* assetObjRaw) {
    if (assetObjRaw) {
        auto*   obj    = reinterpret_cast<HDAssetObj*>(assetObjRaw);
        uint8_t parity = TryReadParityFlag(obj);
        bool isTexture = (obj->assetType == 0);

        if (parity == 0 && isTexture) {
            char name[sizeof(HDAssetObj::name)] = {};
            TryGetAssetName(obj, name, sizeof(name));
            if (name[0] != '\0') {
                fs::path modFile = FindModFile(name);
                if (!modFile.empty()) {
                    if (TrySetParityFlag(obj)) Log("[MOD] parityFlag set (TEX) for: \"%s\"\n", name);
                    RemoveSwap((__int64)obj);
                }
            }
        }

        if (g_Config.verboseLogging) {
            char name[sizeof(HDAssetObj::name)] = {};
            if (TryGetAssetName(obj, name, sizeof(name)))
                if (strstr(name, ".dds")) Log("[PROCESSOR TEX] \"%s\" | Parity: %d\n", name, (int)parity);
        }
    }
    return g_OrigTextureProcessor(fileBuffer, a2, assetObjRaw);
}

// -- Hook: sub_1401726B0 (Skin Change / Hot Reload) ----------------------------
// Called when the player switches character skins.
// Invalidates Cache A entries for modded assets so the subsequent HDResolve does a fresh ring buffer load instead of returning the cached object and bypassing Hook_RingEnqueue.
static __int64 __fastcall Hook_SkinChange(__int64 a1, __int64 a2) {
    InvalidateModdedCacheEntries();
    return g_OrigSkinChange(a1, a2);
}

// -- Hook: sub_140172240 (Character Initialization) ----------------------------
// Called on first character load and on level reload. Same cache invalidation required; Without it the mods stop applying after the initial load.
static __int64 __fastcall Hook_CharInit(__int64 a1, __int64 a2, __int64 a3) {
    InvalidateModdedCacheEntries();
    return g_OrigCharInit(a1, a2, a3);
}

// -- Byte Pattern Signatures ---------------------------------------------------
// Every hooked function above is located at runtime by scanning .text for one of these signatures (PatternScanner.h) rather than a hardcoded RVA.
// So a game update that merely relocates code doesn't break the loader. (Bytes that vary across builds (RIP relative call/lea/mov operands) are wildcarded with "??")
// All patterns below were verified unique within .text on game version 1.0.7 via IDA.
namespace Patterns {
    constexpr const char* LoadEnqueue       = "40 57 48 83 EC 70 45 33 DB 48 8D 05 ?? ?? ?? ?? 48 8B F9 45 8B D3 48 8D 0D ?? ?? ?? ?? 0F 1F 00";
    constexpr const char* OrigReadProcessor = "48 89 5C 24 20 55 41 54 41 55 41 56 41 57 48 83 EC 30 48 8B 1D ?? ?? ?? ?? 4C 8D 25 ?? ?? ?? ?? 48 89 74 24 68";
    constexpr const char* HDResolve         = "44 89 44 24 18 55 53 57 41 54 48 8D AC 24 68 FF FF FF 48 81 EC 98 01 00 00 48 8B F9 48 8D 4C 24 70 48 2B CA";
    constexpr const char* ModelProcessor    = "48 89 5C 24 08 4C 89 44 24 18 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 60 41 8B 00 33 DB 49 8B F0 48 8B E9 41 BD 03 00 00 00";
    constexpr const char* TextureProcessor  = "48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 50 41 8B 00 49 8B F8 48 8B EA 48 8B F1 85 C0";
    constexpr const char* RingEnqueue       = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 8B 35 ?? ?? ?? ?? 48 8B D9 8B C6 33 D2 25 FF 03 00 00 41 B8 B0 00 00 00 48 69 F8 B0 00 00 00";
    constexpr const char* SkinChange        = "48 83 EC 28 48 89 7C 24 20 48 8B F9 E8 ?? ?? ?? ?? 85 C0 74 4D 48 8D 15 ?? ?? ?? ?? 41 B8 B2 00 00 00";
    constexpr const char* CharInit          = "40 55 56 57 48 81 EC 70 02 00 00 49 8B E8 48 8B F2 48 8B F9 E8 ?? ?? ?? ?? 48 85 FF 75 13";
    constexpr const char* FsOpen            = "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 30 41 8B F0 48 8B DA 48 8B F9 48 85 C9 75 22";

    // fopen; Tiny CRT stub that sets the "text mode" flag and tail-jumps into common_fsopen (FsOpen above).
    // Short but the immediate (0x40) followed by an unconditional jmp is an uncommon enough combo to scan for reliably.
    constexpr const char* GameFopen = "41 B8 40 00 00 00 E9 ?? ?? ?? ??";

    // fclose; Statically-linked CRT function. Its prologue (push/mov-frame/sub-rsp/zero-locals) is byte-identical to several sibling file functions (ftell, ftelli64, etc.)
    // And even deep interior anchors like the "and [rcx+3A8h], 0FFFFFFFDh" near the end weren't unique enough to scan for reliably; Every attempt kept matching more than 2 locations so I kept it as a hardcoded RVA.
    constexpr uintptr_t GameFcloseRVA = 0x46FEA8;
}

// -- Data Address Offsets ------------------------------------------------------
// These five globals are arrays/pointers and not functions so they can't be pattern-scanned on their own.
// Instead each is read as a RIP-relative operand at a fixed byte offset *inside* a function already located above via pattern scan.
// This only holds as long as the compiler keeps emitting the same instruction at the same relative position inside that function.
namespace DataOffsets {
    // LoadEnqueue +0x82: 48 8D 05 ?? ?? ?? ??  (lea rax, OriginalSlot[])
    constexpr uintptr_t OriginalSlotArrayOffset = 0x82;
    // RingEnqueue +0x2E: 48 8D 05 ?? ?? ?? ??  (lea rax, RingSlot[])
    constexpr uintptr_t RingSlotArrayOffset     = 0x2E;
    // HDResolve   +0x244: 48 8B 05 ?? ?? ?? ?? (mov rax, cs:CacheArr)
    constexpr uintptr_t CacheArrOffset          = 0x244;
    // HDResolve   +0x33C: 4C 8B 05 ?? ?? ?? ?? (mov r8,  cs:CacheB listHead)
    constexpr uintptr_t CacheBListHeadOffset    = 0x33C;
    // HDResolve   +0x405: FF 05 ?? ?? ?? ??    (inc      cs:fileCount)
    constexpr uintptr_t FileCountOffset         = 0x405;
}

// -- Pipeline Toggle ------------------------------------------------------
// Original Pipeline (LoadEnqueue/OrigReadProcessor/FsOpen redirection for .x64.DRM/.x64.VRM/.SMF/etc.) is disabled due to incomplete reversing and crashing under real use.
// However if you want to enable it anyway just flip this back to true.
constexpr bool kOriginalPipelineEnabled = false;

// -- Hook Installation Helpers --------------------------------------------------
// Resolves a pattern within the already-located .text section and logs the result.
// Returns 0 (and logs an explicit failure) if the pattern isn't found; Almost always means a future game update changed that function's actual code and not just its address, Then the signature needs to be re-derived.
static uintptr_t ResolvePattern(uintptr_t textBase, size_t textSize, const char* pattern, const char* name, uintptr_t exeBase) {
    uintptr_t address = PatternScanner::FindPattern(textBase, textSize, pattern);
    if (!address) {
        Log("[DefianceRMLoader] PATTERN NOT FOUND: %-20s (Game update likely changed this function)\n", name);
        return 0;
    }
    Log("[DefianceRMLoader] %-20s Pattern Matched at RVA: 0x%zX\n", name, address - exeBase);
    return address;
}

static bool CreateHookAtAddress(uintptr_t addr, uintptr_t exeBase, LPVOID hookFn, LPVOID* origOut, const char* name) {
    unsigned char* b = reinterpret_cast<unsigned char*>(addr);

    Log("[DefianceRMLoader] %-20s RVA: 0x%zX | bytes: %02X %02X %02X %02X %02X %02X\n", name, addr - exeBase, b[0], b[1], b[2], b[3], b[4], b[5]);

    MH_STATUS status = MH_CreateHook(reinterpret_cast<LPVOID>(addr), hookFn, origOut);
    if (status != MH_OK) {
        Log("[DefianceRMLoader] FAILED to hook %s: %s\n", name, MH_StatusToString(status));
        return false;
    }
    return true;
}

// -- Public Interface ----------------------------------------------------------
bool HooksInstall() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    g_GameDir = fs::path(exePath).parent_path();
    g_ModsDir = g_GameDir / "mods";

    if (!fs::exists(g_ModsDir)) {
        std::error_code ec;
        fs::create_directory(g_ModsDir, ec);
    }

    InitializeCriticalSection(&g_SwapLock);

    Log("[DefianceRMLoader] Game dir  : %ls\n", g_GameDir.wstring().c_str());
    Log("[DefianceRMLoader] Mods dir  : %ls\n", g_ModsDir.wstring().c_str());

    if (MH_Initialize() != MH_OK) {
        Log("[DefianceRMLoader] MH_Initialize failed\n");
        return false;
    }

    HMODULE   hExe    = GetModuleHandleW(nullptr);
    uintptr_t exeBase = (uintptr_t)hExe;

    uintptr_t textBase = 0;
    size_t    textSize = 0;
    if (!PatternScanner::GetTextSection(hExe, textBase, textSize)) {
        Log("[DefianceRMLoader] Failed to locate .text section; Cannot pattern scan!\n");
        return false;
    }
    Log("[DefianceRMLoader] .text section: Base - 0x%zX | Size - 0x%zX\n", textBase, textSize);

    // -- Resolve all hooked function addresses via byte pattern scan ---------
    auto scanStart = std::chrono::high_resolution_clock::now();

    uintptr_t loadEnqueueAddress       = 0;
    uintptr_t origReadProcessorAddress = 0;
    uintptr_t fsOpenAddress            = 0;
    if (kOriginalPipelineEnabled) {
        loadEnqueueAddress            = ResolvePattern(textBase, textSize, Patterns::LoadEnqueue,       "LoadEnqueue",       exeBase);
        origReadProcessorAddress      = ResolvePattern(textBase, textSize, Patterns::OrigReadProcessor, "OrigReadProcessor", exeBase);
        fsOpenAddress                 = ResolvePattern(textBase, textSize, Patterns::FsOpen,            "FsOpen(common)",    exeBase);
    } else { Log("[DefianceRMLoader] Original Pipeline is disabled in this loader build, Only Remastered assets will be replaced!\n"); }

    uintptr_t hdResolveAddress        = ResolvePattern(textBase, textSize, Patterns::HDResolve,        "HDResolve",        exeBase);
    uintptr_t modelProcessorAddress   = ResolvePattern(textBase, textSize, Patterns::ModelProcessor,   "ModelProcessor",   exeBase);
    uintptr_t textureProcessorAddress = ResolvePattern(textBase, textSize, Patterns::TextureProcessor, "TextureProcessor", exeBase);
    uintptr_t ringEnqueueAddress      = ResolvePattern(textBase, textSize, Patterns::RingEnqueue,      "RingEnqueue",      exeBase);
    uintptr_t skinChangeAddress       = ResolvePattern(textBase, textSize, Patterns::SkinChange,       "SkinChange",       exeBase);
    uintptr_t charInitAddress         = ResolvePattern(textBase, textSize, Patterns::CharInit,         "CharInit",         exeBase);
    uintptr_t gameFopenAddress        = ResolvePattern(textBase, textSize, Patterns::GameFopen,        "GameFopen(fopen)", exeBase);

    auto scanEnd = std::chrono::high_resolution_clock::now();
    Log("[DefianceRMLoader] Pattern scan completed in %lld ms\n", (long long)std::chrono::duration_cast<std::chrono::milliseconds>(scanEnd - scanStart).count());

    bool ok = hdResolveAddress && modelProcessorAddress && textureProcessorAddress && ringEnqueueAddress && skinChangeAddress && charInitAddress && gameFopenAddress;
    if (kOriginalPipelineEnabled) { ok = ok && loadEnqueueAddress && origReadProcessorAddress && fsOpenAddress; }

    if (!ok) {
        Log("[DefianceRMLoader] One or more required patterns failed to resolve; Aborting hook installation!\n");
        return false;
    }

    // GameFclose: No reliable signature exists (See Patterns::GameFcloseRVA comment above) so it's kept as a hardcoded RVA.
    uintptr_t gameFcloseAddr = exeBase + Patterns::GameFcloseRVA;

    g_GameFopen  = reinterpret_cast<PFN_GameFopen>(gameFopenAddress);
    g_GameFclose = reinterpret_cast<PFN_GameFclose>(gameFcloseAddr);
    Log("[DefianceRMLoader] g_GameFopen resolved at RVA: 0x%zX\n", gameFopenAddress - exeBase);
    Log("[DefianceRMLoader] g_GameFclose resolved at RVA: 0x%zX\n", Patterns::GameFcloseRVA);

    // -- Derive data addresses from RIP-relative operands ---------------------
    // See DataOffsets:: above for where each offset/instruction-length pair comes from.
    // OriginalSlot array is only needed by Hook_LoadEnqueue so it's skipped entirely while the original pipeline is disabled because nothing reads it.
    if (kOriginalPipelineEnabled) {
        g_OriginalSlotArrayAddress = PatternScanner::ReadRIPRelative(loadEnqueueAddress + DataOffsets::OriginalSlotArrayOffset, 7, 3);
        Log("[DefianceRMLoader] OriginalSlot Array at RVA: 0x%zX\n", g_OriginalSlotArrayAddress - exeBase);
    }
    g_RingSlotArrayAddress  = PatternScanner::ReadRIPRelative(ringEnqueueAddress + DataOffsets::RingSlotArrayOffset,  7, 3);
    g_CacheArrAddress       = PatternScanner::ReadRIPRelative(hdResolveAddress   + DataOffsets::CacheArrOffset,       7, 3);
    g_CacheBListHeadAddress = PatternScanner::ReadRIPRelative(hdResolveAddress   + DataOffsets::CacheBListHeadOffset, 7, 3);
    g_FileCountAddress      = PatternScanner::ReadRIPRelative(hdResolveAddress   + DataOffsets::FileCountOffset,      6, 2);

    Log("[DefianceRMLoader] RingSlot Array at RVA: 0x%zX\n",   g_RingSlotArrayAddress  - exeBase);
    Log("[DefianceRMLoader] CacheArr Pointer at RVA: 0x%zX\n", g_CacheArrAddress       - exeBase);
    Log("[DefianceRMLoader] CacheB listHead at RVA: 0x%zX\n",  g_CacheBListHeadAddress - exeBase);
    Log("[DefianceRMLoader] File Count at RVA: 0x%zX\n",       g_FileCountAddress      - exeBase);

    bool hooksOk = true;

    // -- CreateFile diagnostics hooks (by export name, always stable) --------
    hooksOk &= (MH_CreateHookApi(L"kernel32", "CreateFileW", &Hook_CreateFileW, reinterpret_cast<LPVOID*>(&g_OrigCreateFileW)) == MH_OK);
    hooksOk &= (MH_CreateHookApi(L"kernel32", "CreateFileA", &Hook_CreateFileA, reinterpret_cast<LPVOID*>(&g_OrigCreateFileA)) == MH_OK);

    if (!hooksOk) {
        Log("[DefianceRMLoader] Failed to hook CreateFile APIs!\n");
        return false;
    }

    // -- Game pipeline hooks (pattern-resolved addresses) ---------------------
    if (kOriginalPipelineEnabled) {
        hooksOk &= CreateHookAtAddress(loadEnqueueAddress,       exeBase, &Hook_LoadEnqueue,       reinterpret_cast<LPVOID*>(&g_OrigLoadEnqueue),       "LoadEnqueue");
        hooksOk &= CreateHookAtAddress(origReadProcessorAddress, exeBase, &Hook_OrigReadProcessor, reinterpret_cast<LPVOID*>(&g_OrigOrigReadProcessor), "OrigReadProcessor");
        hooksOk &= CreateHookAtAddress(fsOpenAddress,            exeBase, &Hook_FsOpen,            reinterpret_cast<LPVOID*>(&g_OrigFsOpen),            "FsOpen(common)");
    }
    hooksOk &= CreateHookAtAddress(hdResolveAddress,             exeBase, &Hook_HDResolve,         reinterpret_cast<LPVOID*>(&g_OrigHDResolve),         "HDResolve");
    hooksOk &= CreateHookAtAddress(modelProcessorAddress,        exeBase, &Hook_ModelProcessor,    reinterpret_cast<LPVOID*>(&g_OrigModelProcessor),    "ModelProcessor");
    hooksOk &= CreateHookAtAddress(textureProcessorAddress,      exeBase, &Hook_TextureProcessor,  reinterpret_cast<LPVOID*>(&g_OrigTextureProcessor),  "TextureProcessor");
    hooksOk &= CreateHookAtAddress(ringEnqueueAddress,           exeBase, &Hook_RingEnqueue,       reinterpret_cast<LPVOID*>(&g_OrigRingEnqueue),       "RingEnqueue");
    hooksOk &= CreateHookAtAddress(skinChangeAddress,            exeBase, &Hook_SkinChange,        reinterpret_cast<LPVOID*>(&g_OrigSkinChange),        "SkinChange");
    hooksOk &= CreateHookAtAddress(charInitAddress,              exeBase, &Hook_CharInit,          reinterpret_cast<LPVOID*>(&g_OrigCharInit),          "CharInit");

    if (!hooksOk) {
        Log("[DefianceRMLoader] One or more hooks failed!\n");
        return false;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        Log("[DefianceRMLoader] MH_EnableHook failed!\n");
        return false;
    }

    // All hooks live: Hook_FsOpen may now act on incoming fopen calls.
    g_HooksReady = true;

    Log("[DefianceRMLoader] All hooks enabled, Watching: \"%ls\" for modded assets!\n", g_ModsDir.wstring().c_str());
    return true;
}

void HooksUninstall() {
    g_HooksReady = false;
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    DeleteCriticalSection(&g_SwapLock);

    // Reset resolved addresses so a future reinstall (if ever supported) doesn't operate on stale pointers from a previous game session.
    g_OriginalSlotArrayAddress = 0;
    g_RingSlotArrayAddress     = 0;
    g_CacheArrAddress          = 0;
    g_CacheBListHeadAddress    = 0;
    g_FileCountAddress         = 0;
    g_GameFopen                = nullptr;
    g_GameFclose               = nullptr;
}
// ------------------------------------------------------------------------------
