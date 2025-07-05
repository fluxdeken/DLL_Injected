#include <windows.h>
#include <string>
#include <vector>

// For finding base address
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... no more deeded
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    // ... no more needed
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // ... no more needed
} PEB, * PPEB;

typedef class _PROCESS {
private:

public:
    uintptr_t pDna;
    uintptr_t baseAddr;
    uintptr_t baseSize;

    _PROCESS() :pDna(0), baseAddr(0), baseSize(0) {}

    bool open(const wchar_t* modName) {
        PPEB peb = (PPEB)__readgsqword(0x60); // use __readfsdword(0x30) on 32-bit
        PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY curr = head->Flink;

        while (curr != head) {
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (_wcsicmp(entry->BaseDllName.Buffer, modName) == 0) {
                baseAddr = (uintptr_t)entry->DllBase;
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)baseAddr;
                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(baseAddr + dos->e_lfanew);
                baseSize = nt->OptionalHeader.SizeOfImage;

                return true;
            }
            curr = curr->Flink;
        }
        return false;
    }

    bool PatternScan(const char* ptrn, size_t ptrnSz,
        const char* mask, uintptr_t* result) {
        if (!baseAddr || !baseSize) return false;

        for (size_t i = 0; i < baseSize - ptrnSz; ++i) {
            bool found = true;
            for (size_t j = 0; mask[j]; ++j) {
                if (mask[j] != '?' && ptrn[j] != *(char*)(baseAddr + i + j)) {
                    found = false;
                    break;
                }
            }
            if (found) {
                *result = (uintptr_t)(baseAddr + i);
                return true;
            }
        }
        return false;
    }

    uintptr_t getPointer(const uintptr_t* offsets, ULONG sz) {
        if (!baseAddr) return 0;
        uintptr_t address = baseAddr;

        for (ULONG i = 0; i < sz - 1; i++) {
            address += offsets[i]; // move to field containing pointer
            address = *reinterpret_cast<uintptr_t*>(address); // dereference
            if (!address) return 0; // optional safety
        }
        return address + offsets[sz - 1]; // final pointer
    }

    int getValue(uintptr_t addr) {
        if (!addr) return 0;
        return *reinterpret_cast<int*>(addr);
    }

    // for buffers
    void patch(const void* data, size_t size, uintptr_t addr) {
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(addr), size, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(reinterpret_cast<void*>(addr), data, size);
        VirtualProtect(reinterpret_cast<void*>(addr), size, oldProtect, &oldProtect);
    }

    // for values
    template<typename T>
    void patch(const T& val, uintptr_t addr) {
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(addr), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(reinterpret_cast<void*>(addr), &val, sizeof(T));
        VirtualProtect(reinterpret_cast<void*>(addr), sizeof(T), oldProtect, &oldProtect);
    }

}PROCESS, * PPROCESS;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
       // PROCESS processObj;
       // PPROCESS process = &processObj;
    }
    return TRUE;
}