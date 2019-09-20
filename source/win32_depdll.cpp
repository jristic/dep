#include <windows.h>
#include <winbase.h>
#include <utility>
#include <detours.h>

static LONG dwSlept = 0;

// Target pointer for the uninstrumented Sleep API.
//
static HANDLE (WINAPI * TrueCreateFileA)(LPCSTR , DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;

// Detour function that replaces the Sleep API.
//
HANDLE WINAPI MyCreateFile(
	LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile)
{
	printf("Intercepting file lpFileName %s! \n", lpFileName);
    return TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
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

	if (fdwReason == DLL_PROCESS_ATTACH) {
		printf("hi from depwin32.dll!\n");
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueCreateFileA, MyCreateFile);
        DetourTransactionCommit();
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
		printf("goodbye from depwin32.dll! \n");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueCreateFileA, MyCreateFile);
        DetourTransactionCommit();
    }

	return TRUE;
}