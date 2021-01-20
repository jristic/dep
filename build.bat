@echo off
rem Pass in the build script directory as it is the project root directory. 
lua build.lua %~dp0 %*
