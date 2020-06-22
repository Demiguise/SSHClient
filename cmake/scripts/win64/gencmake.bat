@echo off
if not defined DevEnvDir (
	call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 10.0.17763.0
)

set buildType=Release
set targetType=Lib

if not "%DEBUG%"=="" set buildType=Debug
if not "%EXE%"=="" set targetType=Exe

echo "Generating project for [%buildType%][%targetType%] configuration"

REM ^ or 'Caret' concats the lines together
cmake -G Ninja -Bbld -H. ^
-DCMAKE_BUILD_TYPE=%buildType% ^
-DSSH_Target_Platform=x64 ^
-DSSH_Target_Type=%targetType% ^
-DSSH_DUMP_BUFFERS=1 ^
-DCMAKE_CXX_COMPILER="C:/Program Files/LLVM/bin/clang-cl.exe" ^
-DCMAKE_C_COMPILER="C:/Program Files/LLVM/bin/clang-cl.exe" ^
-DCMAKE_C_LINKER="C:/Program Files/LLVM/bin/lld-link.exe" ^
-DCMAKE_EXPORT_COMPILE_COMMANDS=1
