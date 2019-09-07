@echo off

call project.bat

set BuildFolder=build

set DetoursIncludePath="external\Detours\include"
set DetoursLibPath="external\Detours\lib.X64"
set DllCompilerFlags=/MTd /nologo /fp:fast /Gm- /GR- /EHa- /Od /Oi /WX /W4 /wd4201 /FC /Z7 /D_CRT_SECURE_NO_WARNINGS /I%DetoursIncludePath% /Fo%BuildFolder%\
set DllLinkerFlags=/DLL /incremental:no /opt:ref /subsystem:console /libpath:%DetoursLibPath% /DEF:source\dllexports.def detours.lib 


if not exist %BuildFolder%\ mkdir %BuildFolder%

cl.exe /LD %DllCompilerFlags% source\win32_depdll.cpp /link %DllLinkerFlags% /OUT:%BuildFolder%\%ProjectName%win32.dll
