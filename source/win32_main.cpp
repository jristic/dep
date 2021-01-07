#include <stdio.h>
#include <windows.h>
#include <detours.h>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable:6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)

void SPrint(char* buf, int buf_size, const char *str, ...)
{
	va_list ptr;
	va_start(ptr,str);
	vsprintf_s(buf,buf_size,str,ptr);
	va_end(ptr);
}

#define Assert(expression, message, ...) 				\
	do { 												\
		__pragma(warning(suppress:4127))				\
		if (!(expression)) {							\
			char __buf[512];							\
			SPrint(__buf, 512,							\
				"/* ---- Assert ---- */ \n"				\
				"LOCATION:  %s@%d		\n"				\
				"CONDITION:  %s			\n"				\
				"MESSAGE: " message "	\n",			\
				__FILE__, __LINE__, 					\
				#expression,							\
				##__VA_ARGS__);							\
			if (IsDebuggerPresent())					\
			{											\
				OutputDebugString(__buf);				\
				DebugBreak();							\
			}											\
			else										\
			{											\
				MessageBoxA(NULL, 						\
					__buf,								\
					"Assert Failed", 					\
					MB_ICONERROR | MB_OK);				\
				exit(-1);								\
			}											\
		}												\
	__pragma(warning(suppress:4127))					\
	} while (0);										\


//////////////////////////////////////////////////////////////////////////////
//
void PrintUsage(void)
{
	printf("Usage:\n"
		   "    dep.exe [options] [command line]\n"
		   "Options:\n"
		   "    /v            : Verbose, display memory at start.\n"
		   "    /?            : This help screen.\n");
}

//////////////////////////////////////////////////////////////////////////////
//
//  This code verifies that the named DLL has been configured correctly
//  to be imported into the target process.  DLLs must export a function with
//  ordinal #1 so that the import table touch-up magic works.
//
struct ExportContext
{
	BOOL    HasOrdinal1;
	ULONG   NumExports;
};

static BOOL CALLBACK ExportCallback(_In_opt_ PVOID pContext,
									_In_ ULONG nOrdinal,
									_In_opt_ LPCSTR pszSymbol,
									_In_opt_ PVOID pbTarget)
{
	(void)pContext;
	(void)pbTarget;
	(void)pszSymbol;

	ExportContext *pec = (ExportContext *)pContext;

	if (nOrdinal == 1)
	{
		pec->HasOrdinal1 = TRUE;
	}
	pec->NumExports++;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
//

//////////////////////////////////////////////////////////////////////////////
//

void TypeToString(DWORD Type, char *pszBuffer, size_t cBuffer)
{
	if (Type == MEM_IMAGE) {
		StringCchPrintfA(pszBuffer, cBuffer, "img");
	}
	else if (Type == MEM_MAPPED) {
		StringCchPrintfA(pszBuffer, cBuffer, "map");
	}
	else if (Type == MEM_PRIVATE) {
		StringCchPrintfA(pszBuffer, cBuffer, "pri");
	}
	else {
		StringCchPrintfA(pszBuffer, cBuffer, "%x", Type);
	}
}

void StateToString(DWORD State, char *pszBuffer, size_t cBuffer)
{
	if (State == MEM_COMMIT) {
		StringCchPrintfA(pszBuffer, cBuffer, "com");
	}
	else if (State == MEM_FREE) {
		StringCchPrintfA(pszBuffer, cBuffer, "fre");
	}
	else if (State == MEM_RESERVE) {
		StringCchPrintfA(pszBuffer, cBuffer, "res");
	}
	else {
		StringCchPrintfA(pszBuffer, cBuffer, "%x", State);
	}
}

void ProtectToString(DWORD Protect, char *pszBuffer, size_t cBuffer)
{
	if (Protect == 0) {
		StringCchPrintfA(pszBuffer, cBuffer, "");
	}
	else if (Protect == PAGE_EXECUTE) {
		StringCchPrintfA(pszBuffer, cBuffer, "--x");
	}
	else if (Protect == PAGE_EXECUTE_READ) {
		StringCchPrintfA(pszBuffer, cBuffer, "r-x");
	}
	else if (Protect == PAGE_EXECUTE_READWRITE) {
		StringCchPrintfA(pszBuffer, cBuffer, "rwx");
	}
	else if (Protect == PAGE_EXECUTE_WRITECOPY) {
		StringCchPrintfA(pszBuffer, cBuffer, "rcx");
	}
	else if (Protect == PAGE_NOACCESS) {
		StringCchPrintfA(pszBuffer, cBuffer, "---");
	}
	else if (Protect == PAGE_READONLY) {
		StringCchPrintfA(pszBuffer, cBuffer, "r--");
	}
	else if (Protect == PAGE_READWRITE) {
		StringCchPrintfA(pszBuffer, cBuffer, "rw-");
	}
	else if (Protect == PAGE_WRITECOPY) {
		StringCchPrintfA(pszBuffer, cBuffer, "rc-");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE)) {
		StringCchPrintfA(pszBuffer, cBuffer, "g--x");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READ)) {
		StringCchPrintfA(pszBuffer, cBuffer, "gr-x");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READWRITE)) {
		StringCchPrintfA(pszBuffer, cBuffer, "grwx");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_WRITECOPY)) {
		StringCchPrintfA(pszBuffer, cBuffer, "grcx");
	}
	else if (Protect == (PAGE_GUARD | PAGE_NOACCESS)) {
		StringCchPrintfA(pszBuffer, cBuffer, "g---");
	}
	else if (Protect == (PAGE_GUARD | PAGE_READONLY)) {
		StringCchPrintfA(pszBuffer, cBuffer, "gr--");
	}
	else if (Protect == (PAGE_GUARD | PAGE_READWRITE)) {
		StringCchPrintfA(pszBuffer, cBuffer, "grw-");
	}
	else if (Protect == (PAGE_GUARD | PAGE_WRITECOPY)) {
		StringCchPrintfA(pszBuffer, cBuffer, "grc-");
	}
	else {
		StringCchPrintfA(pszBuffer, cBuffer, "%x", Protect);
	}
}

static BYTE buffer[65536];

typedef union
{
	struct
	{
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
	} ih;

	IMAGE_NT_HEADERS32 ih32;
	IMAGE_NT_HEADERS64 ih64;
} IMAGE_NT_HEADER;

struct SECTIONS
{
	PBYTE   pbBeg;
	PBYTE   pbEnd;
	CHAR    szName[16];
} Sections[256];
DWORD SectionCount = 0;
DWORD Bitness = 0;

PCHAR FindSectionName(PBYTE pbBase, PBYTE& pbEnd)
{
	for (DWORD n = 0; n < SectionCount; n++) {
		if (Sections[n].pbBeg == pbBase) {
			pbEnd = Sections[n].pbEnd;
			return Sections[n].szName;
		}
	}
	pbEnd = NULL;
	return NULL;
}

ULONG PadToPage(ULONG Size)
{
	return (Size & 0xfff)
		? Size + 0x1000 - (Size & 0xfff)
		: Size;
}

BOOL GetSections(HANDLE hp, PBYTE pbBase)
{
	DWORD beg = 0;
	DWORD cnt = 0;
	SIZE_T done;
	IMAGE_DOS_HEADER idh;

	if (!ReadProcessMemory(hp, pbBase, &idh, sizeof(idh), &done) || done != sizeof(idh)) {
		return FALSE;
	}

	if (idh.e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	IMAGE_NT_HEADER inh;
	if (!ReadProcessMemory(hp, pbBase + idh.e_lfanew, &inh, sizeof(inh), &done) || done != sizeof(inh)) {
		printf("No Read\n");
		return FALSE;
	}

	if (inh.ih.Signature != IMAGE_NT_SIGNATURE) {
		printf("No NT\n");
		return FALSE;
	}

	beg = idh.e_lfanew
		+ FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader )
		+ inh.ih.FileHeader.SizeOfOptionalHeader;
	cnt = inh.ih.FileHeader.NumberOfSections;
	Bitness = (inh.ih32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 32 : 64;
#if 0
	printf("%d %d count=%d\n", beg, Bitness, cnt);
#endif

	IMAGE_SECTION_HEADER ish;
	for (DWORD n = 0; n < cnt; n++) {
		if (!ReadProcessMemory(hp, pbBase + beg + n * sizeof(ish), &ish, sizeof(ish), &done) || done != sizeof(ish)) {
			printf("No Read\n");
			return FALSE;
		}
		Sections[n].pbBeg = pbBase + ish.VirtualAddress;
		Sections[n].pbEnd = pbBase + ish.VirtualAddress + PadToPage(ish.Misc.VirtualSize);
		memcpy(Sections[n].szName, ish.Name, sizeof(ish.Name));
		Sections[n].szName[sizeof(ish.Name)] = '\0';
#if 0
		printf("--- %p %s\n", Sections[n].pbBeg, Sections[n].szName);
#endif
	}
	SectionCount = cnt;

	return TRUE;
}

BOOL DumpProcess(HANDLE hp)
{
	ULONG64 base;
	ULONG64 next;

	MEMORY_BASIC_INFORMATION mbi;

	printf("  %12s %8s %8s: %3s %3s %4s %3s : %8s\n", "Address", "Offset", "Size", "Typ", "Sta", "Prot", "Ini", "Contents");
	printf("  %12s %8s %8s: %3s %3s %4s %3s : %8s\n", "------------", "--------", "--------", "---", "---", "----", "---", "-----------------");

	for (next = 0;;) {
		base = next;
		ZeroMemory(&mbi, sizeof(mbi));
		if (VirtualQueryEx(hp, (PVOID)base, &mbi, sizeof(mbi)) == 0) {
			break;
		}
		if ((mbi.RegionSize & 0xfff) == 0xfff) {
			break;
		}

		next = (ULONG64)mbi.BaseAddress + mbi.RegionSize;

		if (mbi.State == MEM_FREE) {
			continue;
		}

		CHAR szType[16];
		TypeToString(mbi.Type, szType, ARRAYSIZE(szType));
		CHAR szState[16];
		StateToString(mbi.State, szState, ARRAYSIZE(szState));
		CHAR szProtect[16];
		ProtectToString(mbi.Protect, szProtect, ARRAYSIZE(szProtect));
		CHAR szAllocProtect[16];
		ProtectToString(mbi.AllocationProtect, szAllocProtect, ARRAYSIZE(szAllocProtect));

		CHAR szFile[MAX_PATH];
		szFile[0] = '\0';
		DWORD cb = 0;
		PCHAR pszFile = szFile;

		if (base == (ULONG64)mbi.AllocationBase) {
#if 0
			cb = pfGetMappedFileName(hp, (PVOID)mbi.AllocationBase, szFile, ARRAYSIZE(szFile));
#endif
			if (GetSections(hp, (PBYTE)mbi.AllocationBase)) {
				next = base + 0x1000;
				StringCchPrintfA(szFile, ARRAYSIZE(szFile), "%d-bit PE", Bitness);
			}
		}
		if (cb > 0) {
			for (DWORD c = 0; c < cb; c++) {
				szFile[c] = (szFile[c] >= 'a' && szFile[c] <= 'z')
					? szFile[c] - 'a' + 'A' : szFile[c];
			}
			szFile[cb] = '\0';
		}

		if ((pszFile = strrchr(szFile, '\\')) == NULL) {
			pszFile = szFile;
		}
		else {
			pszFile++;
		}

		PBYTE pbEnd;
		PCHAR pszSect = FindSectionName((PBYTE)base, pbEnd);
		if (pszSect != NULL) {
			pszFile = pszSect;
			if (next > (ULONG64)pbEnd) {
				next = (ULONG64)pbEnd;
			}
		}

		CHAR szDesc[128];
		ZeroMemory(&szDesc, ARRAYSIZE(szDesc));
		if (base == (ULONG64)mbi.AllocationBase) {
			StringCchPrintfA(szDesc, ARRAYSIZE(szDesc), "  %12I64x %8I64x %8I64x: %3s %3s %4s %3s : %s",
							 (ULONG64)base,
							 (ULONG64)base - (ULONG64)mbi.AllocationBase,
							 (ULONG64)next - (ULONG64)base,
							 szType,
							 szState,
							 szProtect,
							 szAllocProtect,
							 pszFile);


		}
		else {
			StringCchPrintfA(szDesc, ARRAYSIZE(szDesc), "  %12s %8I64x %8I64x: %3s %3s %4s %3s : %s",
							 "-",
							 (ULONG64)base - (ULONG64)mbi.AllocationBase,
							 (ULONG64)next - (ULONG64)base,
							 szType,
							 szState,
							 szProtect,
							 szAllocProtect,
							 pszFile);
		}
		printf("%s\n", szDesc);
	}
	return TRUE;
}

//////////////////////////////////////////////////////////////////////// main.
//
int CDECL main(int argc, char **argv)
{
	bool NeedHelp = false;
	bool Verbose = false;

	int arg = 1;
	for ( ; arg < argc && (argv[arg][0] == '-' || argv[arg][0] == '/'); arg++)
	{
		char *argn = argv[arg] + 1;
		char *argp = argn;
		while (*argp && *argp != ':' && *argp != '=')
			argp++;
		if (*argp == ':' || *argp == '=')
			*argp++ = '\0';

		switch (argn[0])
		{
			case 'v':                                     // Verbose
			case 'V':
				Verbose = TRUE;
				break;

			case '?':                                     // Help
				NeedHelp = TRUE;
				break;

			default:
				NeedHelp = TRUE;
				printf("dep.exe: Bad argument: %s\n", argv[arg]);
				break;
		}
	}

	if (argc == 1)
		NeedHelp = true;

	if (NeedHelp) {
		PrintUsage();
		return 9001;
	}


	char DepExePath[2048];
	CHAR DllPath[2048];

	// Establish the full path to the current exe
	{
		int copiedSize = GetModuleFileName(nullptr, DepExePath, ARRAYSIZE(DepExePath));
		if (copiedSize == 0)
		{
			printf("dep.exe: Error: failed to get dep exe path. \n");
			return 9002;
		}
		else if (copiedSize == ARRAYSIZE(DepExePath) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			printf("dep.exe: Error: buffer too short for dep exe path. \n");
			return 9002;
		}
	}
	// Establish the full path to the DLL
	{
		char* DllName = "dep64.dll";
		size_t DllNameLength = strlen(DllName);
		memcpy(DllPath, DepExePath, sizeof(DepExePath));
		size_t index = strlen(DllPath) - 1;
		while (DllPath[index] != '\\')
			--index;
		++index; // now index is pointing to the first character of "dep.exe"
		Assert(index + DllNameLength - strlen("dep.exe") < ARRAYSIZE(DllPath), "buffer too short");
		memcpy(&DllPath[index], DllName, DllNameLength+1);
	}

	if (Verbose)
	{
		HMODULE hDll = LoadLibraryExA(DllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (hDll == NULL)
		{
			printf("dep.exe: Error: %s failed to load (error %d).\n",
				DllPath,
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
				DllPath);
			printf("             See help entry DetourCreateProcessWithDllEx in Detours.chm.\n");
			return 9004;
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
	for (; arg < argc; arg++) {
		if (strchr(argv[arg], ' ') != NULL || strchr(argv[arg], '\t') != NULL) {
			StringCchCatA(szCommand, sizeof(szCommand), "\"");
			StringCchCatA(szCommand, sizeof(szCommand), argv[arg]);
			StringCchCatA(szCommand, sizeof(szCommand), "\"");
		}
		else {
			StringCchCatA(szCommand, sizeof(szCommand), argv[arg]);
		}

		if (arg + 1 < argc) {
			StringCchCatA(szCommand, sizeof(szCommand), " ");
		}
	}
	printf("dep.exe: Starting: `%s'\n", szCommand);
	printf("dep.exe:   with `%s'\n", DllPath);
	fflush(stdout);

	DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;

	LPCSTR pszDllPath = DllPath;

	SetLastError(0);
	SearchPathA(NULL, szExe, ".exe", ARRAYSIZE(szFullExe), szFullExe, &pszFileExe);
	if (!DetourCreateProcessWithDllsA(szFullExe[0] ? szFullExe : NULL, szCommand,
									 NULL, NULL, TRUE, dwFlags, NULL, NULL,
									 &si, &pi, 1, &pszDllPath, NULL)) {
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