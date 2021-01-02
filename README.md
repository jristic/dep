# dep
A dependency checker

## Prerequisites
1. A Visual Studio 2017 installation (Community edition will work).
2. A Lua installation on your path.
3. Have luafilesystem and winapi integrated into your Lua installation (I recommend using luarocks to do so).

## Building
1. If necessary, edit shell.bat to correctly point to vcvarsall.bat for your VS installation.
2. You will need to run shell.bat in your environment to set up for compiling with VS tools.
3. Edit build.lua to point to the correct VS install path, Windows Kits path, and version you are using.
4. Run 'build all'. The other valid targets for build are 'exe', 'dll', and 'sample'.
