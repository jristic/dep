#include <string>
#include <strsafe.h>
#include <windows.h>

#include <detours.h>

// Internal headers
#include "depcommon.h"
#include "fileio.h"
#include "md5.h"

// Source files
#include "cacheformat.cpp"
#include "deplogic.cpp"
#include "fileio.cpp"
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

	// Retrieve the current directory.
	fileio::GetCurrentDirectory(szCurrentDirectory, sizeof(szCurrentDirectory));

	md5::Digest digest = deplogic::ComputeCommandStateHash(szFullExe, szCommand, 
		szCurrentDirectory);

	// Make a subfolder for this command state
	std::string subFolder = md5::DigestToString(&digest);
	std::string CommandStatePath = DepCachePath + subFolder + "\\";
	fileio::MakeDirectory(CommandStatePath.c_str());

	std::string depCacheFilePath = CommandStatePath + "latest.dep";

	bool ExecuteProcess = false;

	if (!Force)
	{
		std::string reason;
		bool checkPassed = deplogic::CheckCacheState(depCacheFilePath.c_str(),
			reason);
		ExecuteProcess = !checkPassed;
		if (!checkPassed)
		{
			VerbosePrint("dep.exe: %s\n", reason.c_str());
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
			NULL, NULL, TRUE, dwFlags, NULL, NULL, &si, &pi, DllPath.c_str(), 
			TrueCreateProcessA))
		{
			DWORD dwError = GetLastError();
			printf("dep.exe: DetourCreateProcessWithDllEx failed: %d\n", dwError);
			if (dwError == ERROR_INVALID_HANDLE)
				printf("dep.exe: Mismatched 32/64-bitness between dll and process.\n");
			ExitProcess(9009);
		}

		// Copy payload to DLL
		deplogic::WriteDllPayload(pi.hProcess, subFolder.c_str(), Verbose, Force);

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
