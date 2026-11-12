call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cargo check -p miasma-core --tests --message-format=short 1> C:\work\wp-a4\_chk_out.log 2> C:\work\wp-a4\_chk_err.log
echo EXIT=%errorlevel%
