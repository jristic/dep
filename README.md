# dep (WIP)

Dep is an automatic dependency checking utility for Windows. 

Dep works by having you pass the command you want executed through it, which it creates for you while injecting a DLL into the created process that tracks all files used as input to and output from the process. If the outputs are already up-to-date given the current state of the inputs, Dep skips invoking the command. 

## Status
Dep is a work in progress and does not yet work as advertised. 

## Usage
```
dep.exe [options] [command line]
Options:
	/f	: Force, perform the command even if up to date.
	/v	: Verbose, print info to console and log file.
	/?	: This help screen.
```

## Recommended Application
Dep is intended for use in situations where execution time for a process is high relative to the size of the inputs and outputs (eg shader compilation). If your process uses inputs that are many megabytes or even gigabytes in size, then the time spent having to compute a hash for those inputs will likely eat up any time saved not executing the process. 

## What dep DOES work with
* Programs that take input from files and the command line and write output to other files. 
* Programs that create sub-processes, so long as they also meet all these criteria. 

## What dep DOESN'T work with
* Programs that use a single file as both input and output. 
* Programs that can't be invoked from the command line.
* Programs that use sources like the system clock, the network, or inter-process communication.
* Programs that have non-deterministic output based on their inputs. 
* Programs whose output depends on scanning directories or the existence of files. 

## Prerequisites for building
1. A Visual Studio 2017 installation (Community edition will work).
2. A Lua installation on your path.
3. Have luafilesystem and winapi integrated into your Lua installation (I recommend using luarocks to do so).

## Building
1. If necessary, edit shell.bat to correctly point to vcvarsall.bat for your VS installation.
2. You will need to run shell.bat in your environment to set up for compiling with VS tools.
3. Edit build.lua to point to the correct VS install path, Windows Kits path, and version you are using.
4. Run 'build all'. The other valid targets for build are 'exe', 'dll', and 'sample'.
