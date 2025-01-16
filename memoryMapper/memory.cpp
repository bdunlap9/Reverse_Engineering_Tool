#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <cstdio>
#include <winternl.h>
#include <vector>
#include "../../memoryMapper/capstone/capstone/include/capstone/capstone.h"

#pragma comment(lib, "advapi32.lib")  
#pragma comment(lib, "capstone.lib")
#pragma comment(lib, "Version.lib")

static void DisassembleFunctionToFile(void* addr, size_t size, const char* funcName) {
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("[!] Failed to initialize Capstone for function: %s\n", funcName);
        return;
    }

    char filename[MAX_PATH];
    snprintf(filename, MAX_PATH, "%s.asm", funcName);
    FILE* funcFile;
    errno_t err = fopen_s(&funcFile, filename, "w");
    if (err != 0 || !funcFile) {
        printf("[!] Could not create output file for function %s: %s (Error code: %d)\n", funcName, filename, err);
        cs_close(&handle);
        return;
    }

    count = cs_disasm(handle, (uint8_t*)addr, size, (uint64_t)addr, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            fprintf(funcFile, "0x%" PRIx64 ": %s %s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    }
    else {
        fprintf(funcFile, "[!] Failed to disassemble code at 0x%p\n", addr);
    }

    fclose(funcFile);
    cs_close(&handle);
}

static bool ListModuleExports(HANDLE hProcess, const MODULEINFO& modInfo, const char* modulePath) {
    HANDLE hFile = CreateFileA(modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Could not open file for exports: %s. GLE=%lu\n", modulePath, GetLastError());
        return false;
    }

    HANDLE hFileMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMap) {
        printf("[!] CreateFileMapping for exports failed. GLE=%lu\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    LPVOID localMap = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
    if (!localMap) {
        printf("[!] MapViewOfFile for exports failed. GLE=%lu\n", GetLastError());
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)localMap;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature on exports.\n");
        UnmapViewOfFile(localMap);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)localMap + dos->e_lfanew);
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRVA) {
        printf("No export directory for module: %s\n", modulePath);
        UnmapViewOfFile(localMap);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)localMap + exportRVA);
    DWORD* names = (DWORD*)((BYTE*)localMap + expDir->AddressOfNames);
    DWORD* functions = (DWORD*)((BYTE*)localMap + expDir->AddressOfFunctions);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char* funcName = (char*)localMap + names[i];
        DWORD funcRVA = functions[i];
        void* remoteFuncAddr = (BYTE*)modInfo.lpBaseOfDll + funcRVA;

        printf("[+] Dumping function: %s to file...\n", funcName);
        DisassembleFunctionToFile(remoteFuncAddr, 4096, funcName);
    }

    UnmapViewOfFile(localMap);
    CloseHandle(hFileMap);
    CloseHandle(hFile);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 0;
    }

    DWORD pid = (DWORD)atoi(argv[1]);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("[!] OpenProcess failed. GLE=%lu\n", GetLastError());
        return 1;
    }

    HMODULE hMods[1024] = { 0 };
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        printf("[!] EnumProcessModules failed. GLE=%lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    unsigned int numMods = cbNeeded / sizeof(HMODULE);
    for (unsigned int i = 0; i < numMods; i++) {
        char modPath[MAX_PATH];
        if (!GetModuleFileNameExA(hProcess, hMods[i], modPath, MAX_PATH)) {
            printf("[!] GetModuleFileNameExA failed. GLE=%lu\n", GetLastError());
            continue;
        }
        MODULEINFO modInfo;
        if (!GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
            printf("[!] GetModuleInformation failed. GLE=%lu\n", GetLastError());
            continue;
        }

        printf("[+] Processing module: %s\n", modPath);
        ListModuleExports(hProcess, modInfo, modPath);
    }

    CloseHandle(hProcess);
    printf("[+] Disassembly files generated successfully.\n");
    return 0;
}
