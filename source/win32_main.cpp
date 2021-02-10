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

void MakeDirectory(std::string& directory)
{
	BOOL success = CreateDirectory(directory.c_str(), nullptr);
	if (!success)
	{
		DWORD lastError = GetLastError();
		Assert(lastError == ERROR_ALREADY_EXISTS, 
			"failed to create directory %s, error=%d",
			directory.c_str(), lastError);
	}
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
		Assert(exePos != std::string::npos, "Could not find exe path in string %s",
			DepExePath.c_str());
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
	std::string DepCachePath;
	{
		DepCachePath = DirectoryPath + "depcache\\";
		MakeDirectory(DepCachePath);
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
		HANDLE handle = CreateFile(szFullExe, GENERIC_READ, 0,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		Assert(handle != INVALID_HANDLE_VALUE, "Failed to open exe file %s",
			szFullExe);

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
			success = ReadFile(handle, readBuffer, min(bytesToRead, readSize), 
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
	MakeDirectory(CommandStatePath);

	printf("dep.exe: Starting: '%s', md5=%s\n", szCommand, subFolder.c_str());
	fflush(stdout);

	DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;

	LPCSTR pszDllPath = DllPath.c_str();

	SetLastError(0);
	if (!DetourCreateProcessWithDllsA(szFullExe[0] ? szFullExe : NULL, szCommand,
		NULL, NULL, TRUE, dwFlags, NULL, NULL, &si, &pi, 1, &pszDllPath, NULL))
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
