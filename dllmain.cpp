#include "pch.h"
#include "hook.h"

typedef int(__stdcall* f_MESSAGEBOXW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

DWORD __stdcall HookThread(LPVOID) {
	hook::origFuncAddress = GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxW");
	hook::HookFunc(&hook::HookedMessageBox);
	return 0;
}

// Entry point of DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hModule);
		CreateThread(nullptr, 0, HookThread, nullptr, 0, nullptr);
	}
	return TRUE;
}
