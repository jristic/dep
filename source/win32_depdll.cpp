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

//
// Target pointers for the original functions.
//
static HANDLE (WINAPI * TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
static BOOL (WINAPI * TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
static BOOL (WINAPI * TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
static HMODULE (WINAPI * TrueLoadLibraryW)(LPCWSTR) = LoadLibraryW;


HANDLE WINAPI MyCreateFileW(
	LPCWSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile)
{
	printf("Intercepting file %ls \n", lpFileName);
	return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI MyReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped)
{
	printf("Intercepting read!\n");
	return TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI MyWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped)
{
	printf("Intercepting write!\n");
	return TrueWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

HMODULE WINAPI MyLoadLibraryW(LPCWSTR lpLibFileName)
{
	printf("Intercepting library %ls \n", lpLibFileName);
	return TrueLoadLibraryW(lpLibFileName);
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
		DetourAttach(&(PVOID&)TrueCreateFileW, MyCreateFileW);
		DetourAttach(&(PVOID&)TrueReadFile, MyReadFile);
		DetourAttach(&(PVOID&)TrueWriteFile, MyWriteFile);
		DetourAttach(&(PVOID&)TrueLoadLibraryW, MyLoadLibraryW);
		DetourTransactionCommit();
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
		printf("goodbye from %s! \n", dllName);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)TrueCreateFileW, MyCreateFileW);
		DetourDetach(&(PVOID&)TrueReadFile, MyReadFile);
		DetourDetach(&(PVOID&)TrueWriteFile, WriteFile);
		DetourDetach(&(PVOID&)TrueLoadLibraryW, MyLoadLibraryW);
		DetourTransactionCommit();
	}
	return TRUE;
}