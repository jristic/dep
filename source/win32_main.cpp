#include <string>
#include <strsafe.h>
#include <windows.h>

#include <detours.h>

// Internal headers
#include "depcommon.h"
#include "fileio.h"
#include "md5.h"

// Source files
#include "fileio.cpp"
#include "cacheformat.cpp"
#include "md5.cpp"

//////////////////////////////////////////////////////////////////////////////
//
void PrintUsage(void)
{
	printf("Usage:\n"
		   "	dep.exe [options] [command line]\n"
		   "Options:\n"
		   "	/f		: Force, perform the command even if up to date.\n"
		   "	/v		: Verbose, print info to console and log file.\n"
		   "	/?		: This help screen.\n");
}

md5::Digest ComputeFileHash(HANDLE handle)
{
	uint32_t readSize = 4*1024*1024; // 4 MB
	unsigned char* readBuffer = (unsigned char*)malloc(readSize);
	uint32_t bytesRead = 0;

	LARGE_INTEGER large;
	BOOL success = GetFileSizeEx(handle, &large);
	Assert(success, "Failed to get file size, error=%d", GetLastError());
	Assert(large.QuadPart < UINT_MAX, "File is too large, not supported");
	uint32_t bytesToRead = large.LowPart;

	md5::Context md5Ctx;
	md5::Digest digest;
	md5::Init(&md5Ctx);

	while (bytesRead < bytesToRead)
	{
		OVERLAPPED ovr = {};
		ovr.Offset = bytesRead;
		DWORD bytesReadThisIteration;
		success = TrueReadFile(handle, readBuffer, min(bytesToRead, readSize), 
			&bytesReadThisIteration, &ovr);
		Assert(success, "Failed to read file, error=%d", GetLastError());
		bytesRead += bytesReadThisIteration;
		md5::Update(&md5Ctx, readBuffer, bytesReadThisIteration);
	}

	md5::Final(&digest, &md5Ctx);

	free(readBuffer);

	return digest;
}

#define VerbosePrint(format, ...) if (Verbose) { printf(format, __VA_ARGS__); } else {}

//////////////////////////////////////////////////////////////////////// main.
//
int CDECL main(int argc, char **argv)
{
	bool NeedHelp = false;
	bool Verbose = false;
	bool Force = false;

	int arg = 1;
	for ( ; arg < argc && (argv[arg][0] == '-' || argv[arg][0] == '/'); arg++)
	{
		switch (argv[arg][1])
		{
			case 'v':                                     // Verbose
			case 'V':
				Verbose = true;
				break;
			case 'f':                                     // Force
			case 'F':
				Force = true;
				break;
			case '?':                                     // Help
			case 'h':
			case 'H':
				NeedHelp = true;
				break;
			default:
				NeedHelp = true;
				printf("dep.exe: Bad argument: %s\n", argv[arg]);
				break;
		}
	}

	if (argc == 1 || arg == argc)
		NeedHelp = true;

	if (NeedHelp) {
		PrintUsage();
		return 9001;
	}

	std::string DepExePath;
	std::string DirectoryPath;
	std::string DllPath;
	// Establish the full path to the current exe, its directory, and the dll path
	{
		char PathBuffer[2048];
		fileio::GetModuleFileName(nullptr, PathBuffer, ARRAYSIZE(PathBuffer));
		DepExePath = PathBuffer;

		size_t exePos = DepExePath.rfind(DepExeName);
		Assert(exePos != std::string::npos, "Could not find exe path in string %s",
			DepExePath.c_str());
		DirectoryPath = DepExePath.substr(0, exePos);
		DllPath = DirectoryPath + DepDllName;
	}

	// create the dep cache directory if it doesn't already exist
	std::string DepCachePath;
	{
		DepCachePath = DirectoryPath + "depcache\\";
		fileio::MakeDirectory(DepCachePath.c_str());
	}

	//////////////////////////////////////////////////////////////////////////
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	CHAR szCommand[2048];
	CHAR szExe[1024];
	CHAR szFullExe[1024] = "\0";
	CHAR szCurrentDirectory[1024] = "\0";
	PCHAR pszFileExe = NULL;

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	szCommand[0] = L'\0';

	StringCchCopyA(szExe, sizeof(szExe), argv[arg]);
	for (; arg < argc; arg++)
	{
		StringCchCatA(szCommand, sizeof(szCommand), argv[arg]);
		if (arg + 1 < argc) {
			StringCchCatA(szCommand, sizeof(szCommand), " ");
		}
	}

	// Find the full path of the exe being invoked. 
	{
		DWORD copiedBytes = SearchPathA(NULL, szExe, ".exe", ARRAYSIZE(szFullExe),
			szFullExe, &pszFileExe);
		if (copiedBytes == 0)
		{
			printf("dep.exe: Error: Failed to find exe %s, error=%d \n", 
				szExe, GetLastError());
			return 9005;
		}
		Assert(copiedBytes <= sizeof(szFullExe), "Exe path too long, %d", copiedBytes);
	}

	// Hash the full path to the exe/bat being used, the contents of the exe, 
	//	the command line, and the current working directory.
	md5::Context md5Ctx;
	md5::Digest digest;
	md5::Init(&md5Ctx);
	md5::Update(&md5Ctx, (unsigned char*)szFullExe, strlen(szFullExe));
	md5::Update(&md5Ctx, (unsigned char*)szCommand, strlen(szCommand));
	// The exe file contents
	{
		HANDLE handle = fileio::OpenFileAlways(szFullExe, GENERIC_READ);

		uint32_t readSize = 4*1024*1024; // 4 MB
		unsigned char* readBuffer = (unsigned char*)malloc(readSize);
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
			success = TrueReadFile(handle, readBuffer, min(bytesToRead, readSize), 
				&bytesReadThisIteration, &ovr);
			Assert(success, "Failed to read file, error=%d", GetLastError());
			bytesRead += bytesReadThisIteration;
			md5::Update(&md5Ctx, readBuffer, bytesReadThisIteration);
		}

		free(readBuffer);

		CloseHandle(handle);
	}
	// The current working directory
	{
		DWORD copiedBytes = GetCurrentDirectory(sizeof(szCurrentDirectory), szCurrentDirectory);
		Assert(copiedBytes > 0, "Failed to get current directory, error=%d", GetLastError());
		Assert(copiedBytes <= sizeof(szCurrentDirectory), "Current directory path too long, %d", 
			copiedBytes);
		md5::Update(&md5Ctx, (unsigned char*)szCurrentDirectory, strlen(szCurrentDirectory));
	}
	md5::Final(&digest, &md5Ctx);

	// Make a subfolder for this command state
	std::string subFolder = md5::DigestToString(&digest);
	std::string CommandStatePath = DepCachePath + subFolder + "\\";
	fileio::MakeDirectory(CommandStatePath.c_str());

	std::string depCacheFilePath = CommandStatePath + "latest.dep";

	bool ExecuteProcess = false;

	if (!Force)
	{
		// Read the cache file containing the file info for the most recent invocation,
		//	and if the current state of any file is different from that then we need to
		//	rebuild. 
		HANDLE depCacheFile = fileio::OpenFileOptional(depCacheFilePath.c_str(), GENERIC_READ);
		if (depCacheFile != INVALID_HANDLE_VALUE)
		{
			LARGE_INTEGER large;
			BOOL success = GetFileSizeEx(depCacheFile, &large);
			Assert(success, "Failed to get file size, error=%d", GetLastError());
			Assert(large.QuadPart < UINT_MAX, "File is too large, not supported");

			uint32_t fileSize = large.LowPart;

			unsigned char* depCacheContents = (unsigned char*)malloc(fileSize);

			DWORD bytesRead;
			success = TrueReadFile(depCacheFile, depCacheContents, fileSize, &bytesRead,
				nullptr);
			Assert(success, "Failed to read file, error=%d", GetLastError());
			Assert(bytesRead == fileSize, "Didn't read full file, error=%d ",
				GetLastError());

			CloseHandle(depCacheFile);

			unsigned char* fileReadPtr = depCacheContents;

			uint32_t version = cacheformat::ReadUint(fileReadPtr);

			if (version == DepCacheVersion)
			{
				uint32_t fileCount = cacheformat::ReadUint(fileReadPtr);
				for (uint32_t i = 0 ; i < fileCount ; ++i)
				{
					std::string filePath;
					md5::Digest prevHash = cacheformat::ReadFileInfo(fileReadPtr, filePath);
					HANDLE fileHandle = fileio::OpenFileOptional(filePath.c_str(), GENERIC_READ);
					if (fileHandle != INVALID_HANDLE_VALUE)
					{
						md5::Digest currHash = ComputeFileHash(fileHandle);
						CloseHandle(fileHandle);
						if (memcmp(currHash.bytes, prevHash.bytes, sizeof(currHash.bytes)) != 0)
						{
							ExecuteProcess = true;
							VerbosePrint("dep.exe: %s didn't match previous state, rebuild required.\n",
								filePath.c_str());
							break;
						}
					}
					else
					{
						ExecuteProcess = true;
						VerbosePrint("dep.exe: Couldn't find dependency %s, rebuild required.\n",
							filePath.c_str());
						break;
					}
				}
			}
			else
			{
				ExecuteProcess = true;
				VerbosePrint("dep.exe: Dep cache file version out of date, rebuild required.\n");
			}

			free(depCacheContents);
		}
		else
		{
			// No cache file exists, either this command state hasn't been run before
			//	or it returned an error on the last invocation. 
			VerbosePrint("dep.exe: No cached state for current command state, rebuild required.\n");
			ExecuteProcess = true;
		}
	}

	// Execute the command, if necessary. 
	if (ExecuteProcess || Force)
	{
		VerbosePrint("dep.exe: Starting: '%s', md5=%s\n", szCommand, subFolder.c_str());
		fflush(stdout);

		DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;

		SetLastError(0);
		if (!DetourCreateProcessWithDllEx(szFullExe[0] ? szFullExe : NULL, szCommand,
			NULL, NULL, TRUE, dwFlags, NULL, NULL, &si, &pi, DllPath.c_str(), TrueCreateProcessA))
		{
			DWORD dwError = GetLastError();
			printf("dep.exe: DetourCreateProcessWithDllEx failed: %d\n", dwError);
			if (dwError == ERROR_INVALID_HANDLE)
				printf("dep.exe: Mismatched 32/64 bitness between parent and created process.\n");
			ExitProcess(9009);
		}

		// Copy payload to DLL
		{
			uint32_t flags = Verbose << 0 | Force << 1;
			DWORD payloadSize = sizeof(flags) + 32;
			unsigned char* payload = (unsigned char*)malloc(payloadSize);
			*((uint32_t*)payload) = flags;
			memcpy(payload + sizeof(flags), subFolder.c_str(), 32);
			BOOL success = DetourCopyPayloadToProcess(pi.hProcess, GuidDep, payload, payloadSize);
			Assert(success, "Failed to copy payload, error=%d", GetLastError());
			free(payload);
		}

		ResumeThread(pi.hThread);

		WaitForSingleObject(pi.hProcess, INFINITE);

		DWORD dwResult = 0;
		if (!GetExitCodeProcess(pi.hProcess, &dwResult)) 
		{
			printf("dep.exe: GetExitCodeProcess failed: %d\n", GetLastError());
			return 9010;
		}

		VerbosePrint("dep.exe: Process exited with return value %d\n", dwResult);

		// If the process returned a failure exit code, delete the cache file as it is invalid.
		if (dwResult != 0)
		{
			fileio::DeleteFile(depCacheFilePath.c_str());
		}

		return dwResult;
	}
	else
	{
		VerbosePrint("dep.exe: Skipping invoking command, all files up to date.\n");
		return 0;
	}
}
