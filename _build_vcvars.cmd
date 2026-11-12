@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d C:\work\b13-v4recv
cargo +stable test -p miasma-core --locked --test open_signed_record_v4_test --no-run > _bc3_out.log 2> _bc3_err.log
echo EXITCODE=%ERRORLEVEL% >> _bc3_err.log
