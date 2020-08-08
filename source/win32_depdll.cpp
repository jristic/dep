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
static HANDLE (WINAPI * TrueCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;
static BOOL (WINAPI * TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
static BOOL (WINAPI * TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
static HMODULE (WINAPI * TrueLoadLibraryW)(LPCWSTR) = LoadLibraryW;
static HMODULE (WINAPI * TrueLoadLibraryA)(LPCSTR) = LoadLibraryA;


HANDLE WINAPI MyCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile)
{
	printf("Intercepting file W %ls \n", lpFileName);
	return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile)
{
	printf("Intercepting file A %s \n", lpFileName);
	return TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
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
	printf("Intercepting library W %ls \n", lpLibFileName);
	return TrueLoadLibraryW(lpLibFileName);
}

HMODULE WINAPI MyLoadLibraryA(LPCSTR lpLibFileName)
{
	printf("Intercepting library A %s \n", lpLibFileName);
	return TrueLoadLibraryA(lpLibFileName);
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
		DetourAttach(&(PVOID&)TrueCreateFileA, MyCreateFileA);
		DetourAttach(&(PVOID&)TrueReadFile, MyReadFile);
		DetourAttach(&(PVOID&)TrueWriteFile, MyWriteFile);
		DetourAttach(&(PVOID&)TrueLoadLibraryW, MyLoadLibraryW);
		DetourAttach(&(PVOID&)TrueLoadLibraryA, MyLoadLibraryA);
		DetourTransactionCommit();
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
		printf("goodbye from %s! \n", dllName);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)TrueCreateFileW, MyCreateFileW);
		DetourDetach(&(PVOID&)TrueCreateFileA, MyCreateFileA);
		DetourDetach(&(PVOID&)TrueReadFile, MyReadFile);
		DetourDetach(&(PVOID&)TrueWriteFile, WriteFile);
		DetourDetach(&(PVOID&)TrueLoadLibraryW, MyLoadLibraryW);
		DetourDetach(&(PVOID&)TrueLoadLibraryA, MyLoadLibraryA);
		DetourTransactionCommit();
	}
	return TRUE;
}