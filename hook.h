#pragma once
#include "pch.h"

namespace hook {

	inline char originalBytes[12];
	inline FARPROC origFuncAddress = NULL;

	template<typename T>
	void HookFunc(T* func) {
		if (origFuncAddress == NULL) return;

		memcpy(originalBytes, origFuncAddress, 12);

		void* hookedFuncAddress = reinterpret_cast<void*>(func);

		char patch[12] = {};
		patch[0] = 0x48;
		patch[1] = 0xB8;
		memcpy_s(patch + 2, 8, &hookedFuncAddress, 8);
		patch[10] = 0xFF;
		patch[11] = 0xE0;

		DWORD oldProtect;
		VirtualProtect((LPVOID)origFuncAddress, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy((LPVOID)origFuncAddress, patch, sizeof(patch));
		VirtualProtect((LPVOID)origFuncAddress, sizeof(patch), oldProtect, &oldProtect);
	}

	inline int __stdcall HookedMessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
		OutputDebugStringA("Hello from hooked function.");

		DWORD oldProtect;
		VirtualProtect((LPVOID)origFuncAddress, sizeof(originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy((LPVOID)origFuncAddress, originalBytes, sizeof(originalBytes));
		VirtualProtect((LPVOID)origFuncAddress, sizeof(originalBytes), oldProtect, &oldProtect);

		MessageBoxW(hWnd, lpText, lpCaption, uType);

		return 0;
	}
}
