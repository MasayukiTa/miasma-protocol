call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set CARGO_LOG=trace
set RUST_BACKTRACE=1
cargo check -p miasma-core --lib 1> C:\work\wp-a4\_trace_out.log 2> C:\work\wp-a4\_trace_err.log
echo EXIT=%errorlevel%
