import sys,subprocess,os
real=r"C:\Users\M118A8586\.cargo\bin\rustc.exe"
args=sys.argv[1:]
open(r"C:\work\wp-d3\_wrap.log","a",encoding="utf-8").write("CALL real="+real+" n="+str(len(args))+" :: "+" ".join(args[:6])+"\n")
try:
    r=subprocess.run([real]+args)
    open(r"C:\work\wp-d3\_wrap.log","a",encoding="utf-8").write("  rc="+str(r.returncode)+"\n")
    sys.exit(r.returncode)
except Exception as e:
    open(r"C:\work\wp-d3\_wrap.log","a",encoding="utf-8").write("  EXC="+repr(e)+"\n")
    sys.exit(99)
