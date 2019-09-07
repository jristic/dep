#include <windows.h>
#include <utility>

extern "C" __declspec(dllexport) void testExport() 
{

	printf("hi from testExport!\n");
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

	printf("hi from depwin32.dll!\n");

	return true;
}