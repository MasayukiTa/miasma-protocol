call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cargo fetch 1> C:\work\wp-a4\_fetch_out.log 2> C:\work\wp-a4\_fetch_err.log
echo FETCH_EXIT=%errorlevel%
