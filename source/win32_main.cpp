#include "depcommon.h"

#include <string>
#include <windows.h>
#include <detours.h>

// Source files
#include "win32_processutils.cpp"
#include "md5.cpp"

//////////////////////////////////////////////////////////////////////////////
//
void PrintUsage(void)
{
	printf("Usage:\n"
		   "	dep.exe [options] [command line]\n"
		   "Options:\n"
		   "	/f		: Force, perform the command even if up to date.\n"
		   "	/v		: Verbose, display memory at start.\n"
		   "	/?		: This help screen.\n");
}

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


	char* ExeName = "dep.exe";
	char* DllName = "dep64.dll";
	std::string DepExePath;
	std::string DirectoryPath;
	std::string DllPath;
	// Establish the full path to the current exe, its directory, and the dll path
	{
		char PathBuffer[2048];
		int copiedSize = GetModuleFileName(nullptr, PathBuffer, ARRAYSIZE(PathBuffer));
		if (copiedSize == 0)
		{
			printf("dep.exe: Error: failed to get dep exe path. \n");
			return 9002;
		}
		else if (copiedSize == ARRAYSIZE(PathBuffer) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			printf("dep.exe: Error: buffer too short for dep exe path. \n");
			return 9002;
		}
		DepExePath = PathBuffer;

		size_t exePos = DepExePath.rfind(ExeName);
		Assert(exePos != std::string::npos, "Could not find exe path in string %s", DepExePath.c_str());
		DirectoryPath = DepExePath.substr(0, exePos);
		DllPath = DirectoryPath + DllName;
	}

	if (Verbose)
	{
		HMODULE hDll = LoadLibraryExA(DllPath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (hDll == NULL)
		{
			printf("dep.exe: Error: %s failed to load (error %d).\n",
				DllPath.c_str(),
				GetLastError());
			return 9003;
		}

		ExportContext ec;
		ec.HasOrdinal1 = FALSE;
		ec.NumExports = 0;
		DetourEnumerateExports(hDll, &ec, ExportCallback);
		FreeLibrary(hDll);

		if (!ec.HasOrdinal1)
		{
			printf("dep.exe: Error: %s does not export ordinal #1.\n",
				DllPath.c_str());
			printf("             See help entry DetourCreateProcessWithDllEx in Detours.chm.\n");
			return 9004;
		}
	}

	// create the dep cache directory if it doesn't already exist
	{
		std::string DepCachePath = DirectoryPath + "depcache";
		BOOL success = CreateDirectory(DepCachePath.c_str(), nullptr);
		if (!success)
		{
			DWORD lastError = GetLastError();
			Assert(lastError == ERROR_ALREADY_EXISTS, "failed to create directory, error=%d", lastError);
		}
	}

	//////////////////////////////////////////////////////////////////////////
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	CHAR szCommand[2048];
	CHAR szExe[1024];
	CHAR szFullExe[1024] = "\0";
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

	// TODO: the hash needs to include the full path to the exe/bat being used,
	//	the contents of the exe, and the current working directory.
	md5::Digest digest = md5::ComputeDigest((unsigned char*)szCommand, strlen(szCommand));
	std::string subFolder = md5::DigestToString(&digest);

	printf("dep.exe: Starting: '%s', md5=%s\n", szCommand, subFolder.c_str());
	//printf("dep.exe:   with `%s'\n", DllPath.c_str());
	fflush(stdout);

	DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;

	LPCSTR pszDllPath = DllPath.c_str();

	SetLastError(0);
	SearchPathA(NULL, szExe, ".exe", ARRAYSIZE(szFullExe), szFullExe, &pszFileExe);
	if (!DetourCreateProcessWithDllsA(szFullExe[0] ? szFullExe : NULL, szCommand,
									 NULL, NULL, TRUE, dwFlags, NULL, NULL,
									 &si, &pi, 1, &pszDllPath, NULL))
	{
		DWORD dwError = GetLastError();
		printf("dep.exe: DetourCreateProcessWithDllEx failed: %d\n", dwError);
		if (dwError == ERROR_INVALID_HANDLE) {
#if DETOURS_64BIT
			printf("dep.exe: Can't detour a 32-bit target process from a 64-bit parent process.\n");
#else
			printf("dep.exe: Can't detour a 64-bit target process from a 32-bit parent process.\n");
#endif
		}
		ExitProcess(9009);
	}

	if (Verbose) {
		DumpProcess(pi.hProcess);
	}

	ResumeThread(pi.hThread);

	WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD dwResult = 0;
	if (!GetExitCodeProcess(pi.hProcess, &dwResult)) {
		printf("dep.exe: GetExitCodeProcess failed: %d\n", GetLastError());
		return 9010;
	}

	printf("dep.exe: Process exited with return value %d\n", dwResult);

	return dwResult;
}
