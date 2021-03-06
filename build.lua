local lfs = require("lfs")
local winapi = require("winapi")

local ProjectName = "dep"
local ProjectExe = ProjectName .. ".exe"
local ProjectPath = arg[1]
table.remove(arg, 1)

-- guard against the build script being executed from a different working directory
lfs.chdir(ProjectPath) 

local BuildFolder="built"

local VSInstallPath = "C:/Program Files (x86)/Microsoft Visual Studio/2017/Community/VC/Tools/MSVC/14.16.27023"

local WindowsKitsPath = "C:/Program Files (x86)/Windows Kits"
local WindowsKitsVersion = "10.0.17763.0"
local WindowsKitsLibPath = WindowsKitsPath.."/10/lib/"..WindowsKitsVersion

local VSCommonToolsPath=VSInstallPath.."/bin/Hostx64"
local VSCompiler64Path='"'..VSCommonToolsPath..'/x64/cl.exe"'
local VSCompiler32Path='"'..VSCommonToolsPath..'/x86/cl.exe"'

local VSLib32Path=""..VSInstallPath.."/ATLMFC/lib/x86;"..VSInstallPath.."/lib/x86;"..WindowsKitsPath.."/NETFXSDK/4.6.1/lib/um/x86;"..WindowsKitsLibPath.."/ucrt/x86;"..WindowsKitsLibPath.."/um/x86;"
local VSLib64Path=""..VSInstallPath.."/ATLMFC/lib/x64;"..VSInstallPath.."/lib/x64;"..WindowsKitsPath.."/NETFXSDK/4.6.1/lib/um/x64;"..WindowsKitsLibPath.."/ucrt/x64;"..WindowsKitsLibPath.."/um/x64;"

local DetoursIncludePath="external/Detours/include"
local Detoursx86LibPath="external/Detours/lib.X86"
local Detoursx64LibPath="external/Detours/lib.X64"
local ExeCompilerFlags="/MTd /nologo /fp:fast /Gm- /GR- /EHsc /Od /Oi /WX /W4 /wd4201 /FC /Z7 /utf-8 /D_CRT_SECURE_NO_WARNINGS /I"..DetoursIncludePath.." /Fo"..BuildFolder.."\\"
local ExeLinkerFlags="/incremental:no /opt:ref /subsystem:console /libpath:"..Detoursx64LibPath.." detours.lib User32.lib"
local DllCompilerFlags="/MTd /nologo /fp:fast /Gm- /GR- /EHsc /Od /Oi /WX /W4 /wd4201 /FC /Z7 /utf-8 /D_CRT_SECURE_NO_WARNINGS /I"..DetoursIncludePath.." /Fo"..BuildFolder.."\\"
local DllLinkerFlags="/DLL /incremental:no /opt:ref /subsystem:console /DEF:source\\dllexports.def detours.lib User32.lib Shlwapi.lib"
	
local targets = { "exe", "dll", "sample", "copy", "skip" }
local chosenTargets = {}

local function ShellExecute(command)
	print(command)
	return os.execute(command)
end

for i,v in ipairs(arg) do
	if (v == "all") then
		for i,v in ipairs(targets) do
			table.insert(chosenTargets,v)
		end
	else
		table.insert(chosenTargets, v)
	end
end

print("Building: ", unpack(chosenTargets))

-- make the build folder if it doesn't exist
ShellExecute("if not exist "..BuildFolder.." mkdir "..BuildFolder, true)

local buildFailure = false

local bitness = {"x86", "x64"}
for _,config in ipairs(bitness) do
	local is64 = config == "x64"
	local bitName = is64 and "64" or "32"
	-- TODO: just substitute the x86/x64 into the text so i don't need to have two strings
	local compiler = is64 and VSCompiler64Path or VSCompiler32Path
	local detoursLibPath = is64 and Detoursx64LibPath or Detoursx86LibPath

	local libPath = is64 and VSLib64Path or VSLib32Path
	-- We have to set the LIB path ourselves because it's different for 32bit or 64bit and vcvarsall.bat will only have set it for the bitness we called it with
	winapi.setenv("LIB", libPath)

	for _,target in ipairs(chosenTargets) do
		local ret = 0
		-- we have no need of a 32bit launcher exe
		if target == "exe" and config == "x64" then
			ret = ShellExecute(compiler..' '..ExeCompilerFlags.." source\\win32_main.cpp /Fe"..BuildFolder.."\\"..ProjectExe.." /link "..ExeLinkerFlags .. " /machine:"..config)
		elseif target == "dll" then
			ret = ShellExecute(compiler..' /LDd '..DllCompilerFlags.." source\\win32_depdll.cpp /Fe"..BuildFolder.."\\"..ProjectName..bitName..".dll /link "..DllLinkerFlags.." /libpath:"..detoursLibPath)
		elseif target == "sample" then
			ret = ShellExecute(compiler..' '..ExeCompilerFlags.." source\\win32_sample.cpp /Fe"..BuildFolder.."\\"..ProjectName.."sample"..bitName..".exe /link "..ExeLinkerFlags.." /machine:"..config)
		elseif target == "copy" then
			ret = ShellExecute(compiler..' '..ExeCompilerFlags.." source\\win32_copysample.cpp /Fe"..BuildFolder.."\\".."depcopy"..bitName..".exe /link "..ExeLinkerFlags.." /machine:"..config)
		elseif target == "skip"  and config == "x64" then
			ret = ShellExecute(compiler..' '..ExeCompilerFlags.." source\\win32_depskip.cpp /Fe"..BuildFolder.."\\".."depskip.exe /link "..ExeLinkerFlags.." /machine:"..config)
		end
		if ret ~= 0 then
			print('\27[31mFailure! stopping\27[0m')
			buildFailure = true
		end
		if buildFailure then
			break
		end
	end
	if buildFailure then
		break
	end
end
