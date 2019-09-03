@echo off

call project.bat

set BuildFolder=build

set DetoursIncludePath="Detours\src"
set DetoursLibPath="Detours\lib"
set CommonCompilerFlags=/MTd /nologo /fp:fast /Gm- /GR- /EHa- /Od /Oi /WX /W4 /wd4201 /FC /Z7 /D_CRT_SECURE_NO_WARNINGS /I%DetoursIncludePath% /Fo%BuildFolder%\
set CommonLinkerFlags=/incremental:no /opt:ref /subsystem:console /libpath:%VulkanLibPath% /libpath:%DetoursLibPath% detours.lib

set AdditionalSourceFiles=

if not exist %BuildFolder%\ mkdir %BuildFolder%

cl.exe %CommonCompilerFlags% source/win32_main.cpp %AdditionalSourceFiles% /Fe%ProjectExe% /link %CommonLinkerFlags%
