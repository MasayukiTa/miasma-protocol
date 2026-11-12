call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
rustc --edition 2021 C:\work\wp-a4\_probe.rs -o C:\work\wp-a4\_probe.exe
echo RUSTC_ERRORLEVEL=%errorlevel%
if exist C:\work\wp-a4\_probe.exe (C:\work\wp-a4\_probe.exe & echo RUN_OK) else (echo NO_EXE)
