#include <guiddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

typedef unsigned long int u32;
static_assert(sizeof(u32) == 4, "Didn't get expected size.");

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
			printf("%s\n",__buf);						\
			if (IsDebuggerPresent())					\
			{											\
				OutputDebugString(__buf);				\
				OutputDebugString("\n");				\
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
		__pragma(warning(default:4127))					\
	} while (0);										\


const GUID GuidDep = {
    0xd8e2dc69, 0x3004, 0x453e,
    {0x94, 0x15, 0x19, 0x0e, 0x79, 0xe8, 0x93, 0x52}
};

const uint32_t DepCacheVersion = 2;

const char* DepExeName = "dep.exe";
#if defined(_WIN64)
	const char* DepDllName = "dep64.dll";
#elif defined(_WIN32)
	const char* DepDllName = "dep32.dll";
#else
	#error
#endif

//
// Target pointers for the original versions of intercepted functions (if interception is active).
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
static void (WINAPI * TrueExitProcess)(UINT) = ExitProcess;
