#include "depcommon.h"

#include <windows.h>
#include <winbase.h>
#include <psapi.h>
#include <detours.h>
#include <utility>
#include <string>
#include <mutex>
#include <map>
#include <set>

// Source files
#include "md5.cpp"

#if defined(_WIN64)
const char* DllName = "dep64.dll";
#elif defined(_WIN32)
const char* DllName = "dep32.dll";
#else
	#error
#endif

static void DummyDllIdentifier() { return; }

HANDLE LogFileHandle = INVALID_HANDLE_VALUE;
bool DepSuccess = true;

std::mutex DepInputLock;
std::map<std::string, md5::Digest> DepInputHashes;

std::mutex DepLibraryLock;
std::set<std::string> DepLibraries;

std::mutex DepOutputLock;
std::set<std::string> DepOutputs;

//
// Target pointers for the original functions.
//
static HANDLE (WINAPI * TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
static HANDLE (WINAPI * TrueCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;
static BOOL (WINAPI * TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
static BOOL (WINAPI * TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
static HMODULE (WINAPI * TrueLoadLibraryW)(LPCWSTR) = LoadLibraryW;
static HMODULE (WINAPI * TrueLoadLibraryA)(LPCSTR) = LoadLibraryA;
static HMODULE (WINAPI * TrueLoadLibraryExW)(LPCWSTR,HANDLE,DWORD) = LoadLibraryExW;
static HMODULE (WINAPI * TrueLoadLibraryExA)(LPCSTR,HANDLE,DWORD) = LoadLibraryExA;
static BOOL (WINAPI * TrueCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
static BOOL (WINAPI * TrueCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;


void WriteToLog(const char *format, ...)
{
	Assert(LogFileHandle != INVALID_HANDLE_VALUE, "Log file wasn't created yet?");
	char LogBuffer[2048];

	va_list ptr;
	va_start(ptr,format);
	vsprintf_s(LogBuffer, sizeof(LogBuffer), format, ptr);
	va_end(ptr);

	DWORD bytesWritten;
	BOOL result = TrueWriteFile(LogFileHandle, LogBuffer, (DWORD)strlen(LogBuffer),
		&bytesWritten, nullptr);
	Assert(result, "Failed to write file, last error = %d", GetLastError());
}

std::string ConvertWideString(LPCWSTR string)
{
	size_t mblen = (wcslen(string)+1)*2;
	char* mbstr = (char*)malloc(mblen);
	size_t convertedSize = 0;
	int result = wcstombs_s(&convertedSize, mbstr, mblen, string, mblen);
	Assert(result == 0, "Failed to convert string %ls, wcstombs_s errno=%d", 
		string, result);
	std::string str(mbstr);
	free(mbstr);
	return str;
}

md5::Digest ComputeFileHash(HANDLE handle)
{
	md5::Context md5Ctx;
	md5::Digest digest;
	md5::Init(&md5Ctx);

	uint32_t readSize = 4*1024*1024; // 4 MB
	unsigned char* mem = (unsigned char*)malloc(readSize);
	uint32_t bytesRead = 0;

	LARGE_INTEGER large;
	BOOL success = GetFileSizeEx(handle, &large);
	Assert(success, "Failed to get file size, error=%d", GetLastError());
	Assert(large.QuadPart < UINT_MAX, "File is too large, not supported");
	uint32_t bytesToRead = large.LowPart;

	while (bytesRead < bytesToRead)
	{
		OVERLAPPED ovr = {};
		ovr.Offset = bytesRead;
		DWORD bytesReadThisIteration;
		success = TrueReadFile(handle, mem, min(bytesToRead, readSize), 
			&bytesReadThisIteration, &ovr);
		Assert(success, "Failed to read file, error=%d", GetLastError());
		bytesRead += bytesReadThisIteration;
		md5::Update(&md5Ctx, mem, bytesReadThisIteration);
	}

	md5::Final(&digest, &md5Ctx);

	free(mem);

	// Reset file pointer back to head since ReadFile will have advanced it.
    DWORD result = SetFilePointer(handle, 0, NULL, FILE_BEGIN);
    Assert(result != INVALID_SET_FILE_POINTER, "Failed to set file pointer, error=%d",
    	GetLastError());

	return digest;
}

void ProcessInputFile(std::string& fileName, HANDLE handle)
{
	// check if we already have this file
	bool checkFile = true;
	{
		const std::lock_guard<std::mutex> lock(DepInputLock);
		if (DepInputHashes.find(fileName) != DepInputHashes.end())
		{
			WriteToLog("Repeated file open for %s, skipping \n", fileName.c_str());
			checkFile = false;
		}
		else
		{
			// Insert a blank entry so another thread doesn't come along before
			//	we've finished hashing and think it needs to perform hashing as well. 
			DepInputHashes[fileName] = {};
		}
	}

	if (checkFile)
	{
		md5::Digest digest = ComputeFileHash(handle);
		std::string hash = md5::DigestToString(&digest);

		WriteToLog("Input file %s, hash=%s \n", fileName.c_str(), 
			hash.c_str() );

		{
			const std::lock_guard<std::mutex> lock(DepInputLock);
			DepInputHashes[fileName] = digest;
		}
	}
}

HANDLE WINAPI InterceptCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile)
{
	WriteToLog("Intercepting CreateFileW %ls \n", lpFileName);
	HANDLE handle = TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
		lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	DWORD errorToPreserve = GetLastError();

	// Early out if create file failed - this is a valid flow. Don't track it. 
	if (handle == INVALID_HANDLE_VALUE)
	{
		WriteToLog("Failed to open file %ls \n", lpFileName);
		SetLastError(errorToPreserve);
		return handle;
	}

	// Check that dwDesiredAccess isn't both read AND write - this is not valid. 
	if ((dwDesiredAccess & GENERIC_READ) != 0 && (dwDesiredAccess & GENERIC_WRITE) != 0)
	{
		WriteToLog("File opened with both read and write, this is not valid usage - %ls \n",
			lpFileName);
		DepSuccess = false;
		SetLastError(errorToPreserve);
		return handle;
	}

	// TODO: check that this file wasn't previously opened with a different dwDesiredAccess

	std::string fileName = ConvertWideString(lpFileName);

	if ((dwDesiredAccess & GENERIC_READ) != 0)
	{
		ProcessInputFile(fileName, handle);
	}
	else if ((dwDesiredAccess & GENERIC_WRITE) != 0)
	{
		const std::lock_guard<std::mutex> lock(DepOutputLock);
		DepOutputs.insert(fileName);
		WriteToLog("Output file %s \n", fileName.c_str());
	}

	SetLastError(errorToPreserve);
	return handle;
}

HANDLE WINAPI InterceptCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile)
{
	WriteToLog("Intercepting CreateFileA %s \n", lpFileName);
	HANDLE handle = TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	DWORD errorToPreserve = GetLastError();

	// Early out if create file failed - this is a valid flow. Don't track it. 
	if (handle == INVALID_HANDLE_VALUE)
	{
		WriteToLog("Failed to open file %s \n", lpFileName);
		SetLastError(errorToPreserve);
		return handle;
	}

	// Check that dwDesiredAccess isn't both read AND write - this is not valid. 
	if ((dwDesiredAccess & GENERIC_READ) != 0 && (dwDesiredAccess & GENERIC_WRITE) != 0)
	{
		WriteToLog("File opened with both read and write, this is not valid usage - %s \n",
			lpFileName);
		DepSuccess = false;
		SetLastError(errorToPreserve);
		return handle;
	}

	// TODO: check that this file wasn't previously opened with a different dwDesiredAccess

	std::string fileName(lpFileName);

	if ((dwDesiredAccess & GENERIC_READ) != 0)
	{
		ProcessInputFile(fileName, handle);
	}
	else if ((dwDesiredAccess & GENERIC_WRITE) != 0)
	{
		const std::lock_guard<std::mutex> lock(DepOutputLock);
		DepOutputs.insert(fileName);
		WriteToLog("Output file %s \n", fileName.c_str());
	}

	SetLastError(errorToPreserve);
	return handle;
}

// BOOL WINAPI InterceptReadFile(
// 	HANDLE       hFile,
// 	LPVOID       lpBuffer,
// 	DWORD        nNumberOfBytesToRead,
// 	LPDWORD      lpNumberOfBytesRead,
// 	LPOVERLAPPED lpOverlapped)
// {
// 	WriteToLog("Intercepting read!\n");
// 	return TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
// 		lpOverlapped);
// }

// BOOL WINAPI InterceptWriteFile(
// 	HANDLE       hFile,
// 	LPCVOID      lpBuffer,
// 	DWORD        nNumberOfBytesToWrite,
// 	LPDWORD      lpNumberOfBytesWritten,
// 	LPOVERLAPPED lpOverlapped)
// {
// 	WriteToLog("Intercepting write!\n");
// 	return TrueWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
// 		lpNumberOfBytesWritten, lpOverlapped);
// }

void ProcessLibrary(HMODULE module)
{
	std::string libPath;
	{
		DWORD PathBufferSize = 2048;
		char* PathBuffer = (char*)malloc(PathBufferSize);
		DWORD copiedSize = GetModuleFileName(module, PathBuffer, PathBufferSize);
		if (copiedSize == 0)
		{
			Assert(false, "depdll: Error: failed to get dep dll path. \n");
		}
		else if (copiedSize == PathBufferSize &&
			GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			Assert(false, "depdll: Error: buffer too short for dep dll path. \n");
		}

		libPath = PathBuffer;
		free(PathBuffer);
	}

	{
		const std::lock_guard<std::mutex> lock(DepLibraryLock);
		DepLibraries.insert(libPath);
		WriteToLog("Library full path %s \n", libPath.c_str());
	}
}

HMODULE WINAPI InterceptLoadLibraryW(LPCWSTR lpLibFileName)
{
	WriteToLog("Intercepting LoadLibraryW %ls \n", lpLibFileName);

	HMODULE module = TrueLoadLibraryW(lpLibFileName);
	DWORD errorToPreserve = GetLastError();

	// Early out if load failed - this is a valid flow. Don't track it. 
	if (module == NULL)
	{
		WriteToLog("Failed to load library %ls \n", lpLibFileName);
		SetLastError(errorToPreserve);
		return module;
	}

	ProcessLibrary(module);

	SetLastError(errorToPreserve);
	return module;
}

HMODULE WINAPI InterceptLoadLibraryA(LPCSTR lpLibFileName)
{
	WriteToLog("Intercepting LoadLibraryA %s \n", lpLibFileName);

	HMODULE module = TrueLoadLibraryA(lpLibFileName);
	DWORD errorToPreserve = GetLastError();

	// Early out if load failed - this is a valid flow. Don't track it. 
	if (module == NULL)
	{
		WriteToLog("Failed to load library %s \n", lpLibFileName);
		SetLastError(errorToPreserve);
		return module;
	}

	ProcessLibrary(module);

	SetLastError(errorToPreserve);
	return module;
}

HMODULE WINAPI InterceptLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	WriteToLog("Intercepting LoadLibraryExW %ls \n", lpLibFileName);

	HMODULE module = TrueLoadLibraryExW(lpLibFileName, hFile, dwFlags);
	DWORD errorToPreserve = GetLastError();

	// Early out if load failed - this is a valid flow. Don't track it. 
	if (module == NULL)
	{
		WriteToLog("Failed to load library %ls \n", lpLibFileName);
		SetLastError(errorToPreserve);
		return module;
	}

	if ((dwFlags & LOAD_LIBRARY_AS_DATAFILE) != 0 ||
		(dwFlags & LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE) != 0)
	{
		WriteToLog("Unsupported loadlibrary, dep failure");
		DepSuccess = false;
		SetLastError(errorToPreserve);
		return module;
	}

	ProcessLibrary(module);

	SetLastError(errorToPreserve);
	return module;
}

HMODULE WINAPI InterceptLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	WriteToLog("Intercepting LoadLibraryExA %s \n", lpLibFileName);

	HMODULE module = TrueLoadLibraryExA(lpLibFileName, hFile, dwFlags);
	DWORD errorToPreserve = GetLastError();

	// Early out if load failed - this is a valid flow. Don't track it. 
	if (module == NULL)
	{
		WriteToLog("Failed to load library %s \n", lpLibFileName);
		SetLastError(errorToPreserve);
		return module;
	}

	if ((dwFlags & LOAD_LIBRARY_AS_DATAFILE) != 0 ||
		(dwFlags & LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE) != 0)
	{
		WriteToLog("Unsupported loadlibrary, dep failure");
		DepSuccess = false;
		SetLastError(errorToPreserve);
		return module;
	}

	ProcessLibrary(module);

	SetLastError(errorToPreserve);
	return module;
}

BOOL WINAPI InterceptCreateProcessA(
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
	WriteToLog("Intercepting create process A %s %s \n", lpApplicationName, lpCommandLine);

	// TODO: implement
	DepSuccess = false;
	WriteToLog("Dep failure, createprocess not implemented \n");

	return TrueCreateProcessA(
		lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, 
		lpStartupInfo, lpProcessInformation);
}

BOOL WINAPI InterceptCreateProcessW(
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
	WriteToLog("Intercepting create process W %ls %ls \n", lpApplicationName, lpCommandLine);

	// TODO: implement
	DepSuccess = false;
	WriteToLog("Dep failure, createprocess not implemented \n");

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
	DetourAttach(&(PVOID&)TrueCreateFileW, InterceptCreateFileW);
	DetourAttach(&(PVOID&)TrueCreateFileA, InterceptCreateFileA);
	// DetourAttach(&(PVOID&)TrueReadFile, InterceptReadFile);
	// DetourAttach(&(PVOID&)TrueWriteFile, InterceptWriteFile);
	DetourAttach(&(PVOID&)TrueLoadLibraryW, InterceptLoadLibraryW);
	DetourAttach(&(PVOID&)TrueLoadLibraryA, InterceptLoadLibraryA);
	DetourAttach(&(PVOID&)TrueLoadLibraryExW, InterceptLoadLibraryExW);
	DetourAttach(&(PVOID&)TrueLoadLibraryExA, InterceptLoadLibraryExA);
	DetourAttach(&(PVOID&)TrueCreateProcessA, InterceptCreateProcessA);
	DetourAttach(&(PVOID&)TrueCreateProcessW, InterceptCreateProcessW);
	DetourTransactionCommit();
}

void DllDetoursDetach()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)TrueCreateFileW, InterceptCreateFileW);
	DetourDetach(&(PVOID&)TrueCreateFileA, InterceptCreateFileA);
	// DetourDetach(&(PVOID&)TrueReadFile, InterceptReadFile);
	// DetourDetach(&(PVOID&)TrueWriteFile, InterceptWriteFile);
	DetourDetach(&(PVOID&)TrueLoadLibraryW, InterceptLoadLibraryW);
	DetourDetach(&(PVOID&)TrueLoadLibraryA, InterceptLoadLibraryA);
	DetourDetach(&(PVOID&)TrueLoadLibraryExW, InterceptLoadLibraryExW);
	DetourDetach(&(PVOID&)TrueLoadLibraryExA, InterceptLoadLibraryExA);
	DetourDetach(&(PVOID&)TrueCreateProcessA, InterceptCreateProcessA);
	DetourDetach(&(PVOID&)TrueCreateProcessW, InterceptCreateProcessW);
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
		// For debugging
		//while( !::IsDebuggerPresent() )
		//	::Sleep( 100 ); // to avoid 100% CPU load
		
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
		else if (copiedSize == ARRAYSIZE(PathBuffer) &&
			GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			Assert(false, "depdll: Error: buffer too short for dep dll path. \n");
		}

		std::string DllPath = PathBuffer;

		size_t dllPos = DllPath.rfind(DllName);
		Assert(dllPos != std::string::npos, "Could not find dll name in string %s",
			DllPath.c_str());
		std::string DirectoryPath = DllPath.substr(0, dllPos);

		std::string DepCachePath = DirectoryPath + "depcache\\";

		SYSTEMTIME time;
		GetLocalTime(&time);

		char tmpBuffer[128];
		snprintf(tmpBuffer, sizeof(tmpBuffer), "%d_%.2d_%.2d__%.2d_%.2d_%.2d.log",
			time.wYear,	time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
		std::string logFilePath = DepCachePath + tmpBuffer;
		
		LogFileHandle = TrueCreateFileA(logFilePath.c_str(), GENERIC_WRITE, 0,
			nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (LogFileHandle == INVALID_HANDLE_VALUE)
		{ 
			int iteration = 1;
			DWORD lastError = GetLastError();
			while (LogFileHandle == INVALID_HANDLE_VALUE && 
				lastError == ERROR_FILE_EXISTS)
			{
				snprintf(tmpBuffer, sizeof(tmpBuffer), "%d_%.2d_%.2d__%.2d_%.2d_%.2d__%d.log",
					time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond,
					iteration);
				logFilePath = DepCachePath + tmpBuffer;
				LogFileHandle = TrueCreateFileA(logFilePath.c_str(), GENERIC_WRITE, 0, nullptr,
					CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
				++iteration;
			}
		}
		Assert(LogFileHandle != INVALID_HANDLE_VALUE, "Failed to create log file %s",
			logFilePath.c_str());

		LPSTR commandLine = GetCommandLine();
		WriteToLog("Invocation: Dll=%s commandLine=%s \n", DllPath.c_str(), commandLine);

		DllDetoursAttach();
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		DllDetoursDetach();

		// Write out .dep file containing results for given inputs
		// TODO: Mark failure during course of execution (ie. if too large file 
		// 	was used, or read+write permission) and invalidate the results here if so. 
		if (DepSuccess)
		{
			for (auto iter : DepInputHashes)
			{
				// TODO: add sanity check that input file contents are still the same.
				WriteToLog("Dep input %s hash=%s \n", iter.first.c_str(), 
					md5::DigestToString(&iter.second).c_str());
			}
			for (std::string output : DepOutputs)
			{
				HANDLE handle = TrueCreateFileA(output.c_str(), GENERIC_READ, 0,
					nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
				Assert(handle != INVALID_HANDLE_VALUE, "Failed to open output file %s",
					output.c_str());

				md5::Digest digest = ComputeFileHash(handle);
				std::string hash = md5::DigestToString(&digest);

				WriteToLog("Dep output %s, hash=%s \n", output.c_str(), hash.c_str());
			}
			for (std::string library : DepLibraries)
			{
				HANDLE handle = TrueCreateFileA(library.c_str(), GENERIC_READ, 0,
					nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
				Assert(handle != INVALID_HANDLE_VALUE, "Failed to open library file %s",
					library.c_str());

				md5::Digest digest = ComputeFileHash(handle);
				std::string hash = md5::DigestToString(&digest);

				WriteToLog("Dep library %s, hash=%s \n", library.c_str(), hash.c_str());
			}
		}
		else
		{
			WriteToLog("Dep failed, see log above. No results cache will be written.\n");
		}

		CloseHandle(LogFileHandle);
	}
	return TRUE;
}