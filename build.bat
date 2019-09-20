@echo off

call project.bat

set BuildFolder=build

set DetoursIncludePath="external\Detours\include"
set DetoursLibPath="external\Detours\lib.X64"
set CommonCompilerFlags=/MTd /nologo /fp:fast /Gm- /GR- /EHa- /Od /Oi /WX /W4 /wd4201 /FC /Z7 /D_CRT_SECURE_NO_WARNINGS /I%DetoursIncludePath% /Fo%BuildFolder%\
set CommonLinkerFlags=/incremental:no /opt:ref /subsystem:console /libpath:%DetoursLibPath% detours.lib

set AdditionalSourceFiles=

if not exist %BuildFolder%\ mkdir %BuildFolder%

setlocal
call shell x64
cl.exe %CommonCompilerFlags% source/win32_main.cpp %AdditionalSourceFiles% /Fe%ProjectExe% /link %CommonLinkerFlags%
endlocal
