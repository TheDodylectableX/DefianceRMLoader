// -----------------------------------------------------------------------------
// Byte-Pattern / Signature Scanner used to locate game functions and data by their machine code fingerprint instead of a hardcoded RVA (Relative Virtual Address).
// This is what makes the mod loader survive game updates that shift code around without changing the underlying instruction sequence but only the *address* of a function changes and not the bytes that make it up. (Aside from RIP-relative operands which are wildcarded out when building each signature).
//
// -- Pattern Syntax ------------------------------------------------------------
//   Space-separated hex byte pairs, with "?" or "??" as a full-byte wildcard: "48 8D 05 ?? ?? ?? ?? 48 8B F9"
//   Wildcard out anything that's RIP-relative (lea/mov/call/jmp operands into data or other code) - Those 4 byte displacements change everytime the compiler relays out the binary even when the instruction itself is otherwise unchanged, Keep stable opcode/register/immediate bytes as-is.
//
// -- Usage ----------------------------------------------------------------------
//   uintptr_t addr = PatternScan::FindPatternInModule(GetModuleHandleW(nullptr), "48 8D 05 ?? ?? ?? ?? 48 8B F9");
//   if (addr) { ... }
//   For globals that aren't standalone functions (arrays, cache pointers), Read them as a RIP-relative operand at a known offset inside a function you've already located: uintptr_t target = PatternScan::ReadRipRelative(funcAddr + offset, instrLen, dispOffset);
// -----------------------------------------------------------------------------
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <sstream>
#include <vector>

namespace PatternScanner {
    struct PatternByte { // One byte of a parsed pattern: Either a fixed value to match exactly or a wildcard that matches anything.
        uint8_t Value;
        bool    isWildcard;
    };

    // Parses a pattern string like "40 57 48 83 EC 70 ?? ?? 45 33 DB" into a sequence of PatternByte, Tokens "?" and "??" are both treated as a full-byte wildcard.
    // (Both show up depending on which disassembler version a signature was originally copied from)

    inline std::vector<PatternByte> ParsePattern(const char* Pattern) {
        std::vector<PatternByte> Result;
        std::istringstream ISS(Pattern);
        std::string Token;

        while (ISS >> Token) {
            if (Token == "?" || Token == "??") { Result.push_back({0, true}); }
            else {
                uint8_t byteValue = static_cast<uint8_t>(strtoul(Token.c_str(), nullptr, 16));
                Result.push_back({byteValue, false});
            }
        }
        return Result;
    }

    // Scans for the first occurrence of Pattern. Returns the absolute address of the match or 0 if not found.
    // Implementation Note: This is a plain nested loop scan rather than Boyer-Moore-Horspool or something similar.
    // For a one-time startup scan over a single .text section (tens of MB) - This is fast enough in practice
    // Almost every candidate offset fails on the very first byte so the inner loop exits via break immediately in the overwhelming majority of cases.
    inline uintptr_t FindPattern(uintptr_t StartAddress, size_t Size, const std::vector<PatternByte>& Pattern) {
        if (Pattern.empty() || Size < Pattern.size()) return 0;

        const uint8_t* Base          = reinterpret_cast<const uint8_t*>(StartAddress);
        const size_t   PatternLength = Pattern.size();
        const size_t   scanLength    = Size - PatternLength;

        for (size_t i = 0; i < scanLength; ++i) {
            bool Found = true;
            for (size_t j = 0; j < PatternLength; ++j) {
                if (!Pattern[j].isWildcard && Base[i+j] != Pattern[j].Value) {
                    Found = false;
                    break;
                }
            }
            if (Found) return StartAddress + i;
        }
        return 0;
    }

    // Convenience overload that parses the pattern string inline.
    inline uintptr_t FindPattern(uintptr_t StartAddress, size_t Size, const char* PatternString) { return FindPattern(StartAddress, Size, ParsePattern(PatternString)); }

    // Locate the .text section of a loaded PE module in memory. Returns false if the module's headers don't look like a valid PE image which should never happen for a module handle obtained from GetModuleHandle anyway.
    inline bool GetTextSection(HMODULE hModule, uintptr_t& outBase, size_t& outSize) {
        if (!hModule) return false;

        auto* DOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto* NTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(hModule) + DOSHeader->e_lfanew);
        if (NTHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        auto* Section = IMAGE_FIRST_SECTION(NTHeaders);
        for (WORD i = 0; i < NTHeaders->FileHeader.NumberOfSections; ++i, ++Section) {
            if (strncmp(reinterpret_cast<const char*>(Section->Name), ".text", 5) == 0) {
                outBase = reinterpret_cast<uintptr_t>(hModule) + Section->VirtualAddress;
                outSize = Section->Misc.VirtualSize;
                return true;
            }
        }
        return false; // No .text section found for some reason?
    }

    // Scan the .text section of hModule for PatternString. Returns the absolute address of the match or 0 if the section couldn't be found or the pattern doesn't appear in it.
    inline uintptr_t FindPatternInModule(HMODULE hModule, const char* PatternString) {
        uintptr_t Base = 0;
        uintptr_t Size = 0;
        if (!GetTextSection(hModule, Base, Size)) return 0;
        return FindPattern(Base, Size, PatternString);
    }

    // Reads a RIP-relative operand out of an instruction at instructionAddress. x64 RIP-relative addressing encodes a signed 32-bit displacement that's relative to the address of the *next* instruction (not the current one) so the formula is always:
    // target             = instructionAddress + instructionSize + disp32
    // instructionSize    = total length of the instruction in bytes (e.g. 7 for a "48 8D 05 ?? ?? ?? ??" lea, 6 for an "FF 05 ?? ?? ?? ??" inc)
    // displacementOffset = byte offset *within* the instruction where the 4-byte displacement starts (e.g. 3 for the lea above, 2 for the inc)

    // This only holds for the *exact* instruction encoding it was measured against so if a future build's compiler picks a different instruction for the same logical operation (Different register, Different addressing mode) instructionSize/displacementOffset need to be re-derived from a fresh IDA disassembly of that instruction.
    inline uintptr_t ReadRIPRelative(uintptr_t InstructionAddress, int InstructionSize, int DisplacementOffset) {
        int32_t Displacement = *reinterpret_cast<int32_t*> (InstructionAddress + DisplacementOffset);
        return InstructionAddress + InstructionSize + Displacement;
    }
}
// -----------------------------------------------------------------------------
