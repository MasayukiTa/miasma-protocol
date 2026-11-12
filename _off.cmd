call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cargo check -p miasma-core --lib --offline --frozen 1> C:\work\wp-a4\_off_out.log 2> C:\work\wp-a4\_off_err.log
echo OFF_EXIT=%errorlevel%
