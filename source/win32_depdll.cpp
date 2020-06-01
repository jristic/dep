#include <windows.h>
#include <winbase.h>
#include <utility>
#include <detours.h>

#if defined(_WIN64)
const char* dllName = "depwin64.dll";
#elif defined(_WIN32)
const char* dllName = "depwin32.dll";
#else
	#error
#endif

// Target pointer for the uninstrumented Sleep API.
//
static HANDLE (WINAPI * TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
static BOOL (WINAPI * TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;

// Detour function that replaces the Sleep API.
//
HANDLE WINAPI MyCreateFile(
	LPCWSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile)
{
	printf("Intercepting file!\n");
	return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL MyReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped)
{
	printf("Intercepting read!\n");
	return TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	(void)hinstDLL;
	(void)fdwReason;
	(void)lpvReserved;

	if (DetourIsHelperProcess())
		return TRUE;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		printf("hi from %s!\n", dllName);
		DetourRestoreAfterWith();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)TrueCreateFileW, MyCreateFile);
		DetourAttach(&(PVOID&)TrueReadFile, MyReadFile);
		DetourTransactionCommit();
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
		printf("goodbye from %s! \n", dllName);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)TrueCreateFileW, MyCreateFile);
		DetourDetach(&(PVOID&)TrueReadFile, MyReadFile);
		DetourTransactionCommit();
	}
	return TRUE;
}