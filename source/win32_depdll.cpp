#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <detours.h>
#include <utility>
#include <string>
#include <mutex>
#include <map>
#include <set>

// Internal headers
#include "depcommon.h"
#include "fileio.h"
#include "md5.h"

// Source files
#include "cacheformat.cpp"
#include "deplogic.cpp"
#include "fileio.cpp"
#include "md5.cpp"


static void DummyDllIdentifier() { return; }

std::string LogFilePath;
HANDLE LogFileHandle = INVALID_HANDLE_VALUE;
std::mutex LogFileLock;
bool DepSuccess = true;

bool DepVerbose;
bool DepForce;

u32 InterceptedExitCode;

std::string DepExePath;
std::string DepDllPath;
std::string DepCachePath;
std::string DepCommandStatePath;
std::string WindowsSystemPath;

std::mutex DepInputLock;
std::map<std::string, md5::Digest> DepInputHashes;

std::mutex DepLibraryLock;
std::set<std::string> DepLibraries;

std::mutex DepOutputLock;
std::set<std::string> DepOutputs;



void WriteToLog(const char *format, ...)
{
	if (DepVerbose)
	{
		const std::lock_guard<std::mutex> lock(LogFileLock);

		Assert(LogFileHandle != INVALID_HANDLE_VALUE, "Log file wasn't created yet?");
		char LogBuffer[2048];

		va_list ptr;
		va_start(ptr,format);
		vsprintf_s(LogBuffer, sizeof(LogBuffer), format, ptr);
		va_end(ptr);

		fileio::WriteFile(LogFileHandle, LogBuffer, (u32)strlen(LogBuffer));
	}
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
		md5::Digest digest = deplogic::ComputeFileHash(handle);
		// Reset file pointer back to head since ReadFile will have advanced it.
		//	Since this is an intercepted file create, it needs to be reset to its
		//	initial state as if it had just been opened (since to the user it has). 
		fileio::ResetFilePointer(handle);

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

std::string GetLibraryPath(HMODULE module)
{
	DWORD PathBufferSize = 2048;
	char* PathBuffer = (char*)malloc(PathBufferSize);
	fileio::GetModuleFileName(module, PathBuffer, PathBufferSize);

	std::string libPath = PathBuffer;
	free(PathBuffer);

	return libPath;
}

void ProcessLibrary(HMODULE module)
{
	std::string libPath = GetLibraryPath(module);

	// Don't include windows system DLLs. They don't affect results that we care 
	//	about, and they use a directory redirect that is opaque to us so it's hard
	//	to correctly compute their file state between 32/64-bit processes. 
	bool skipDll = StrStrIA(libPath.c_str(), WindowsSystemPath.c_str()) != nullptr;

	if (skipDll)
	{
		WriteToLog("Skipping library %s \n", libPath.c_str());
	}
	else
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
		WriteToLog("Unsupported loadlibrary, dep failure.\n");
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
		WriteToLog("Unsupported loadlibrary, dep failure'\n");
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
	WriteToLog("Intercepting CreateProcessA %s %s \n", lpApplicationName, lpCommandLine);

	// TODO: get the EXE for the process we're creating
	std::string exe;
	if (lpApplicationName)
	{
		exe = lpApplicationName;
	}
	else
	{

	}

	// TODO: if that EXE is dep, then remove it and use the first arg on the command line as the exe


	BOOL success = TrueCreateProcessA(
		lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, 
		lpStartupInfo, lpProcessInformation);
	DWORD errorToPreserve = GetLastError();

	SetLastError(errorToPreserve);
	return success;
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
	WriteToLog("Intercepting CreateProcessW %ls %ls \n", lpApplicationName, lpCommandLine);

	// TODO: implement
	DepSuccess = false;
	WriteToLog("Dep failure, createprocess not implemented \n");

	return TrueCreateProcessW(
		lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, 
		lpStartupInfo, lpProcessInformation);
}

void WINAPI InterceptExitProcess(UINT exitCode)
{
	WriteToLog("Intercepting ExitProcess %d\n", exitCode);
	InterceptedExitCode = exitCode;
	return TrueExitProcess(exitCode);
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
	DetourAttach(&(PVOID&)TrueExitProcess, InterceptExitProcess);
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
	DetourDetach(&(PVOID&)TrueExitProcess, InterceptExitProcess);
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
		// while( !::IsDebuggerPresent() )
		// 	::Sleep( 100 ); // to avoid 100% CPU load
		
		HMODULE hm = NULL;
		if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCSTR) &DummyDllIdentifier, &hm) == 0)
		{
			int ret = GetLastError();
			Assert(false, "GetModuleHandle failed, error = %d\n", ret);
		}

		DepDllPath = GetLibraryPath(hm);

		size_t dllPos = DepDllPath.rfind(DepDllName);
		Assert(dllPos != std::string::npos, "Could not find dll name in string %s",
			DepDllPath.c_str());
		std::string DirectoryPath = DepDllPath.substr(0, dllPos);

		DepExePath = DirectoryPath + DepExeName;

		DepCachePath = DirectoryPath + "depcache\\";

		// Extract payload data from the detours section.
		char commandStateHash[32+1];
		HMODULE next = NULL;
		while ((next = DetourEnumerateModules(next)) != NULL)
		{
			DWORD payloadSize = 0;
			unsigned char* payload = (unsigned char*)DetourFindPayload(next, GuidDep, 
				&payloadSize);
			if (!payload)
				continue;
			uint32_t flags;
			Assert(payloadSize == sizeof(flags) + 32, "Invalid payload, size = %d", 
				payloadSize);
			flags = *((uint32_t*)payload);
			DepVerbose = (flags & 1) != 0;
			DepForce = (flags & 2) != 0;
			memcpy(commandStateHash, payload + sizeof(flags), 32);
			commandStateHash[32] = 0;
			break;
		}

		if (DepVerbose)
		{
			SYSTEMTIME time;
			GetLocalTime(&time);

			char tmpBuffer[128];
			snprintf(tmpBuffer, sizeof(tmpBuffer), "%d_%.2d_%.2d__%.2d_%.2d_%.2d.log",
				time.wYear,	time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
			LogFilePath = DepCachePath + tmpBuffer;
			
			LogFileHandle = fileio::CreateFileTryNew(LogFilePath.c_str(), GENERIC_WRITE);
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
					LogFilePath = DepCachePath + tmpBuffer;
					LogFileHandle = fileio::CreateFileTryNew(LogFilePath.c_str(), GENERIC_WRITE);
					++iteration;
				}
			}
			Assert(LogFileHandle != INVALID_HANDLE_VALUE, "Failed to create log file %s",
				LogFilePath.c_str());
		}

		LPSTR commandLine = GetCommandLine();
		WriteToLog("Invocation: Dll=%s commandLine=%s \n", DepDllPath.c_str(), commandLine);


		DepCommandStatePath = DepCachePath + commandStateHash + "\\";

		WriteToLog("Command state hash: %s \n", commandStateHash);

		// Find the system directory
		{
			char PathBuffer[1024];
			UINT copiedBytes = GetSystemDirectory(PathBuffer, sizeof(PathBuffer));
			Assert(copiedBytes > 0, "Failed to get system directory, error=%d", 
				GetLastError())
			Assert(copiedBytes <= sizeof(PathBuffer), 
				"Buffer too short for system directory path, chars=%d", copiedBytes);
			WindowsSystemPath = std::string(PathBuffer);
			WriteToLog("System directory: %s\n", PathBuffer);
		}

		DllDetoursAttach();
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		DllDetoursDetach();

		// Write out .dep file containing results for given inputs
		if (DepSuccess && InterceptedExitCode == 0)
		{
			std::string depCachePath = DepCommandStatePath + "latest.dep";
			HANDLE depCacheFile = fileio::CreateFileOverwrite(depCachePath.c_str(), 
				GENERIC_WRITE);

			cacheformat::WriteUint(depCacheFile, DepCacheVersion);

			size_t fileCount = DepLibraries.size() + DepInputHashes.size() + 
				DepOutputs.size(); 
			cacheformat::WriteUint(depCacheFile, (uint32_t)fileCount);

			for (std::string library : DepLibraries)
			{
				HANDLE handle = fileio::OpenFileAlways(library.c_str(), GENERIC_READ);

				md5::Digest digest = deplogic::ComputeFileHash(handle);
				std::string hash = md5::DigestToString(&digest);

				CloseHandle(handle);

				cacheformat::WriteFileInfo(depCacheFile, library.c_str(), digest);

				WriteToLog("Dep library %s, hash=%s \n", library.c_str(), hash.c_str());
			}
			for (auto iter : DepInputHashes)
			{
				// TODO: add sanity check that input file contents are still the same.
				const char* inputPath = iter.first.c_str();
				md5::Digest& digest = iter.second;
				std::string hashString = md5::DigestToString(&digest);

				cacheformat::WriteFileInfo(depCacheFile, inputPath, digest);

				WriteToLog("Dep input %s hash=%s \n", inputPath, hashString.c_str());
			}
			for (std::string output : DepOutputs)
			{
				HANDLE handle = fileio::OpenFileAlways(output.c_str(), GENERIC_READ);

				md5::Digest digest = deplogic::ComputeFileHash(handle);
				std::string hash = md5::DigestToString(&digest);

				CloseHandle(handle);

				cacheformat::WriteFileInfo(depCacheFile, output.c_str(), digest);

				WriteToLog("Dep output %s, hash=%s \n", output.c_str(), hash.c_str());
			}

			CloseHandle(depCacheFile);
		}
		else if (InterceptedExitCode != 0)
		{
			WriteToLog("Intercepted process returned fail code, %d. No cache "
				"file will be saved.\n", InterceptedExitCode);
		}
		else
		{
			WriteToLog("Dep failed, see log above. No results cache will be written.\n");
			if (DepVerbose)
			{
				printf("%s: Dep failed, see log file %s for info.\n", DepDllName, 
					LogFilePath.c_str());
			}
			else
			{
				printf("%s: Dep failed, use verbose flag (/v) for info.\n", DepDllName);
			}
		}

		if (DepVerbose)
		{
			CloseHandle(LogFileHandle);
		}
	}
	return TRUE;
}