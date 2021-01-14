# dep
Dep is an automatic dependency checking utility for Windows. 
Dep works by having you pass the command you want executed through it, which it creates for you while injecting a DLL into the created process that tracks all files used as input to and output from the process. If the outputs are already up-to-date given the current state of the inputs, Dep skips invoking the command. 

## Prerequisites for building
1. A Visual Studio 2017 installation (Community edition will work).
2. A Lua installation on your path.
3. Have luafilesystem and winapi integrated into your Lua installation (I recommend using luarocks to do so).

## Building
1. If necessary, edit shell.bat to correctly point to vcvarsall.bat for your VS installation.
2. You will need to run shell.bat in your environment to set up for compiling with VS tools.
3. Edit build.lua to point to the correct VS install path, Windows Kits path, and version you are using.
4. Run 'build all'. The other valid targets for build are 'exe', 'dll', and 'sample'.
