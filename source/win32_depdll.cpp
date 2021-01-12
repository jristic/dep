#include "depcommon.h"

#include <windows.h>
#include <winbase.h>
#include <utility>
#include <detours.h>
#include <string>

#if defined(_WIN64)
const char* DllName = "dep64.dll";
#elif defined(_WIN32)
const char* DllName = "dep32.dll";
#else
	#error
#endif

static void DummyDllIdentifier() { return; }

HANDLE LogFileHandle = INVALID_HANDLE_VALUE;

//
// Target pointers for the original functions.
//
static HANDLE (WINAPI * TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
static HANDLE (WINAPI * TrueCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;
static BOOL (WINAPI * TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
static BOOL (WINAPI * TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
static HMODULE (WINAPI * TrueLoadLibraryW)(LPCWSTR) = LoadLibraryW;
static HMODULE (WINAPI * TrueLoadLibraryA)(LPCSTR) = LoadLibraryA;
static BOOL (WINAPI * TrueCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
static BOOL (WINAPI * TrueCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;

void WriteToLog(const char* string)
{
	printf("test: %s \n", string);
	// if (LogFileHandle != INVALID_HANDLE_VALUE)
	{ 
		DWORD bytesWritten;
		BOOL result = TrueWriteFile(LogFileHandle, string, (DWORD)strlen(string), &bytesWritten, nullptr);
		Assert(result, "Failed to write file, last error = %d", GetLastError());
	}
	// else
	// {
	// 	printf(string);
	// }
}

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
	WriteToLog("Intercepting read!\n");
	return TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI MyWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped)
{
	WriteToLog("Intercepting write!\n");
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

BOOL WINAPI MyCreateProcessA(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	printf("Intercepting create process A %s %s \n", lpApplicationName, lpCommandLine);
	return TrueCreateProcessA(
		lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, 
		lpStartupInfo, lpProcessInformation);
}

BOOL WINAPI MyCreateProcessW(
	LPCWSTR               lpApplicationName,
	LPWSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	printf("Intercepting create process W %ls %ls \n", lpApplicationName, lpCommandLine);
	return TrueCreateProcessW(
		lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, 
		lpStartupInfo, lpProcessInformation);
}

void DllDetoursAttach()
{
	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)TrueCreateFileW, MyCreateFileW);
	DetourAttach(&(PVOID&)TrueCreateFileA, MyCreateFileA);
	DetourAttach(&(PVOID&)TrueReadFile, MyReadFile);
	DetourAttach(&(PVOID&)TrueWriteFile, MyWriteFile);
	DetourAttach(&(PVOID&)TrueLoadLibraryW, MyLoadLibraryW);
	DetourAttach(&(PVOID&)TrueLoadLibraryA, MyLoadLibraryA);
	DetourAttach(&(PVOID&)TrueCreateProcessA, MyCreateProcessA);
	DetourAttach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
	DetourTransactionCommit();
}

void DllDetoursDetach()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)TrueCreateFileW, MyCreateFileW);
	DetourDetach(&(PVOID&)TrueCreateFileA, MyCreateFileA);
	DetourDetach(&(PVOID&)TrueReadFile, MyReadFile);
	DetourDetach(&(PVOID&)TrueWriteFile, WriteFile);
	DetourDetach(&(PVOID&)TrueLoadLibraryW, MyLoadLibraryW);
	DetourDetach(&(PVOID&)TrueLoadLibraryA, MyLoadLibraryA);
	DetourDetach(&(PVOID&)TrueCreateProcessA, MyCreateProcessA);
	DetourDetach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
	DetourTransactionCommit();
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
		DllDetoursAttach();

		HMODULE hm = NULL;
		if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
		        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		        (LPCSTR) &DummyDllIdentifier, &hm) == 0)
		{
		    int ret = GetLastError();
		    Assert(false, "GetModuleHandle failed, error = %d\n", ret);
		}

		char PathBuffer[2048];
		int copiedSize = GetModuleFileName(hm, PathBuffer, ARRAYSIZE(PathBuffer));
		if (copiedSize == 0)
		{
			Assert(false, "depdll: Error: failed to get dep dll path. \n");
		}
		else if (copiedSize == ARRAYSIZE(PathBuffer) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			Assert(false, "depdll: Error: buffer too short for dep dll path. \n");
		}

		std::string DllPath = PathBuffer;

		size_t dllPos = DllPath.rfind(DllName);
		Assert(dllPos != std::string::npos, "Could not find dll name in string %s", DllPath.c_str());
		std::string DirectoryPath = DllPath.substr(0, dllPos);
		printf("directoryPath %s\n", DirectoryPath.c_str());

		std::string DepCachePath = DirectoryPath + "depcache\\";

		SYSTEMTIME time;
		GetLocalTime(&time);

		char buffer[64];
		snprintf(buffer, sizeof(buffer), "%d_%.2d_%.2d__%.2d_%.2d_%.2d.log", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
		std::string logFilePath = DepCachePath + buffer;
		printf("logFilePath %s\n", logFilePath.c_str());

		LogFileHandle = TrueCreateFileA(logFilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		Assert(LogFileHandle != INVALID_HANDLE_VALUE, "Failed to create file %s", logFilePath.c_str());

		WriteToLog(DllName);

		LPSTR commandLine = GetCommandLine();
		WriteToLog(commandLine);

	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		DllDetoursDetach();

		CloseHandle(LogFileHandle);
	}
	return TRUE;
}