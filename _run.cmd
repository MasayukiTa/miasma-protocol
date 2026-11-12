call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
echo VCVARS_ERRORLEVEL=%errorlevel%
where cl
where link
echo ---RUN CHECK---
cargo check -p miasma-core --lib --message-format=short
echo CARGO_ERRORLEVEL=%errorlevel%
