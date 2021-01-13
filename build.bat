@echo off
rem It's necessary to use the full path to the script so that we know our absolute path.
lua build.lua %~dp0 %*
