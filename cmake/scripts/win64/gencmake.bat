@echo off
if not defined DevEnvDir (
	call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 10.0.17763.0
)

set buildType=Release

if not "%DEBUG%"=="" set buildType=DebugFull

echo "Generating project for [%buildType%] configuration"

REM ^ or 'Caret' concats the lines together
cmake -G Ninja -Bbld -H. ^
-DCMAKE_BUILD_TYPE=%buildType% ^
-DSSH_Target_Platform=x64 ^
-DCMAKE_CXX_COMPILER="C:/Program Files/LLVM/bin/clang-cl.exe" ^
-DCMAKE_C_COMPILER="C:/Program Files/LLVM/bin/clang-cl.exe" ^
-DCMAKE_C_LINKER="C:/Program Files/LLVM/bin/lld-link.exe" ^
-DCMAKE_EXPORT_COMPILE_COMMANDS=1
