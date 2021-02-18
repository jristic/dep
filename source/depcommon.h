#include <stdio.h>
#include <stdarg.h>
#include <guiddef.h>

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