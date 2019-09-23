@echo off

setlocal

	call project.bat

	set BuildFolder=build

	set DetoursIncludePath="external\Detours\include"
	set Detoursx86LibPath="external\Detours\lib.X86"
	set Detoursx64LibPath="external\Detours\lib.X64"
	set ExeCompilerFlags=/MTd /nologo /fp:fast /Gm- /GR- /EHa- /Od /Oi /WX /W4 /wd4201 /FC /Z7 /D_CRT_SECURE_NO_WARNINGS /I%DetoursIncludePath% /Fo%BuildFolder%\
	set ExeLinkerFlags=/incremental:no /opt:ref /subsystem:console /libpath:%Detoursx64LibPath% detours.lib
	set DllCompilerFlags=/MTd /nologo /fp:fast /Gm- /GR- /EHa- /Od /Oi /WX /W4 /wd4201 /FC /Z7 /D_CRT_SECURE_NO_WARNINGS /I%DetoursIncludePath% /Fo%BuildFolder%\
	set DllLinkerFlags=/DLL /incremental:no /opt:ref /subsystem:console /DEF:source\dllexports.def detours.lib 
	

	if not exist %BuildFolder%\ mkdir %BuildFolder%

	if "%1" == "exe" goto buildexe
	if "%1" == "all" goto buildexe
	goto checkbuilddll

	:buildexe
	rem Build Exe
	setlocal
		call shell x64
		cl.exe %ExeCompilerFlags% source/win32_main.cpp %AdditionalSourceFiles% /Febuild\%ProjectExe% /link %ExeLinkerFlags%
	endlocal

	:checkbuilddll

	if "%1" == "dll" goto builddll
	if "%1" == "all" goto builddll
	goto checkbuildsample

	:builddll
	rem Build 64-bit DLL
	setlocal
		call shell x64
		cl.exe /LD %DllCompilerFlags% source\win32_depdll.cpp /link %DllLinkerFlags% /libpath:%Detoursx64LibPath% /OUT:build\%ProjectName%64.dll
	endlocal
	rem Build 32-bit DLL
	setlocal
		call shell x86
		cl.exe /LD %DllCompilerFlags% source\win32_depdll.cpp /link %DllLinkerFlags% /libpath:%Detoursx86LibPath% /OUT:build\%ProjectName%32.dll
	endlocal

	:checkbuildsample

	if "%1" == "sample" goto buildsample
	if "%1" == "all" goto buildsample
	goto end

	:buildsample
	rem Build 32-bit sample
	setlocal
		call shell x86
		cl.exe %ExeCompilerFlags% source/win32_sample.cpp %AdditionalSourceFiles% /Febuild\%ProjectName%sample32.exe /link %ExeLinkerFlags%
	endlocal
	rem Build 64-bit sample
	setlocal
		call shell x64
		cl.exe %ExeCompilerFlags% source/win32_sample.cpp %AdditionalSourceFiles% /Febuild\%ProjectName%sample64.exe /link %ExeLinkerFlags%
	endlocal

	:end

endlocal