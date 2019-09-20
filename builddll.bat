@echo off

call project.bat

set BuildFolder=build

set DetoursIncludePath="external\Detours\include"
set DllCompilerFlags=/MTd /nologo /fp:fast /Gm- /GR- /EHa- /Od /Oi /WX /W4 /wd4201 /FC /Z7 /D_CRT_SECURE_NO_WARNINGS /I%DetoursIncludePath% /Fo%BuildFolder%\


if not exist %BuildFolder%\ mkdir %BuildFolder%

setlocal
call shell x86
set DetoursLibPath="external\Detours\lib.X86"
set DllLinkerFlags=/DLL /incremental:no /opt:ref /subsystem:console /libpath:%DetoursLibPath% /DEF:source\dllexports.def detours.lib 
cl.exe /LD %DllCompilerFlags% source\win32_depdll.cpp /link %DllLinkerFlags% /OUT:%ProjectName%win32.dll
endlocal

setlocal
call shell x64
set DetoursLibPath="external\Detours\lib.X64"
set DllLinkerFlags=/DLL /incremental:no /opt:ref /subsystem:console /libpath:%DetoursLibPath% /DEF:source\dllexports.def detours.lib 
cl.exe /LD %DllCompilerFlags% source\win32_depdll.cpp /link %DllLinkerFlags% /OUT:%ProjectName%win64.dll
endlocal
