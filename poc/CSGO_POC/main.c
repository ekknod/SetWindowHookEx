/*
 * @ekknod2022
 *
 * This tool is just proof of concept, You can use it as learning material.
 * 
 * this application is going to store r_drawothermodels value at first,
 * then later applying the stored value at game server.
 *
 * Compile this program as (x86/Release)
 */

#include <Windows.h>
#include <stdio.h>

BOOLEAN CheckMask(unsigned char* base, unsigned char* pattern, unsigned char* mask)
{
	for (; *mask; ++base, ++pattern, ++mask) {
		if (*mask == 'x' && *base != *pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

VOID* FindPattern(unsigned char* base, DWORD size, unsigned char* pattern, unsigned char* mask)
{
	size -= strlen((const char*)mask);
	for (DWORD i = 0; i <= size; ++i) {
		VOID* addr = &base[i];
		if (CheckMask(addr, pattern, mask)) {
			return addr;
		}
	}
	return NULL;
}

void ExecuteFunction(HMODULE dll, DWORD address, DWORD thread_id)
{
	HHOOK handle = SetWindowsHookExA(WH_GETMESSAGE, (HOOKPROC)address, (HINSTANCE)dll, thread_id);

	PostThreadMessageA(thread_id, WM_NULL, 0, 0);

	Sleep(50);

	UnhookWindowsHookEx(handle);
}

int main(void)
{
	printf("\033[0;37m[CS:GO SetWindowHookEx r_drawothermodels 2]\n\n");


	printf("\033[0;33m");

	HWND hwnd = FindWindowA("Valve001", 0);

	//
	// this is important to check, it would do it for every window
	//
	if (hwnd == 0)
	{
		printf("[-] target window not found\n");
		return getchar();
	}

	printf("[+] Target window found: 0x%lx\n", (DWORD)hwnd);

	//
	// load target dll
	//
	HMODULE dll = LoadLibraryExA(
		"C:\\Program Files (x86)\\Steam\\steamapps\\common\\Counter-Strike Global Offensive\\bin\\engine.dll",
		NULL, DONT_RESOLVE_DLL_REFERENCES);


	if (dll == 0)
	{
		printf("[-] target dll not found\n");
		return getchar();
	}

	printf("[+] Target DLL found: 0x%lx\n", (DWORD)dll);

	IMAGE_DOS_HEADER *hdr = (IMAGE_DOS_HEADER*)dll;
	IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)((char*)hdr + hdr->e_lfanew);

	DWORD target_address = (DWORD)FindPattern((unsigned char *)dll,
		nt->OptionalHeader.SizeOfImage,
		"\xFF\x50\x40\x6A\x00\x68\x00\x00\x00\x00",
		"xxxxxx????"
		);

	if (target_address == 0)
	{
		printf("[-] target address not found\n");
		return getchar();
	}

	DWORD offset_SetValue = target_address + 0x03;
	DWORD offset_StoreValue = offset_SetValue - 0x171;

	printf("[+] SetValue %lx\n", offset_SetValue);
	printf("[+] StoreValue %lx\n", offset_StoreValue);

	DWORD thread_id = GetWindowThreadProcessId(hwnd, 0);
	if (thread_id == 0)
	{
		printf("[-] target thread not found\n");
		FreeLibrary(dll);
		return getchar();
	}

	printf(
		"\n\033[0;31m[+] 1. Open CS:GO Main Menu\n"
		"[+] 2. Open CS:GO console\n"
		"[+] 3. Set sv_cheats 1\n"
		"[+] 4. Set r_drawothermodels 2\n"
		"\nWhen you are ready, you can continue the program . . .\n"
	);

	getchar();

	ExecuteFunction(dll, offset_StoreValue, thread_id);

	printf(
		"\033[0;36m[+] 5. Set r_drawothermodels 1\n"
		"[+] 6. Set sv_cheats 0\n"
		"[+] 7. Join InGame server\n"
		"\nWhen you are ready, you can continue the program . . .\n"
	);

	getchar();

	ExecuteFunction(dll, offset_SetValue, thread_id);

	FreeLibrary(dll);
	
	printf(
		"\033[0;32m[+] We are now ready\n"
		"\nYou can now close the application safely . . .\n"	
	);

	printf("\033[0;37m");

	return getchar();
}

