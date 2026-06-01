# Capture the real CmRcViewer's plaintext SCCM/RDP frames by hooking the SSPI
# seal/unseal (EncryptMessage / DecryptMessage). Polls for the export because at
# spawn time sspicli.dll is not loaded yet. Small frames only (the WLC channel
# RPC messages), skipping the graphics flood.
import frida, sys, time, subprocess

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TARGET-HOST"
EXE = r"\\SHARE\RemoteTool\CmRcViewer.exe"
MAXLEN = int(sys.argv[2]) if len(sys.argv) > 2 else 400
SECS = int(sys.argv[3]) if len(sys.argv) > 3 else 18
OUT = r"C:\Users\you\dev\sccm-rc\frida-frames.txt"

JS = r"""
var ENC=0, DEC=0, encHooked=false, decHooked=false;
function dumpBufs(pMsg, dir){
  try{
    var cBuffers = pMsg.add(4).readU32();
    var pBuffers = pMsg.add(8).readPointer();
    for (var i=0;i<cBuffers;i++){
      var b = pBuffers.add(i*12);
      var cb=b.readU32(), type=b.add(4).readU32(), pv=b.add(8).readPointer();
      if (type===1 && cb>0 && cb<__MAX__){ send({d:dir,len:cb}, pv.readByteArray(cb)); }
    }
  }catch(e){}
}
var timer = setInterval(function(){
  if (!encHooked){
    var pe = Module.findExportByName(null,'EncryptMessage');
    if (pe){ encHooked=true; Interceptor.attach(pe,{onEnter:function(a){ENC++; dumpBufs(a[2],'C');}});
             send({d:'INFO',msg:'EncryptMessage hooked @'+pe}); }
  }
  if (!decHooked){
    var pd = Module.findExportByName(null,'DecryptMessage');
    if (pd){ decHooked=true; Interceptor.attach(pd,{onEnter:function(a){this.m=a[1];DEC++;},
             onLeave:function(){dumpBufs(this.m,'S');}});
             send({d:'INFO',msg:'DecryptMessage hooked @'+pd}); }
  }
  if (encHooked && decHooked) clearInterval(timer);
}, 150);
setInterval(function(){ send({d:'INFO',msg:'ENC='+ENC+' DEC='+DEC}); }, 3000);
""".replace("__MAX__", str(MAXLEN))

fh = open(OUT, "w")
def on_message(msg, data):
    if msg.get('type') == 'send':
        p = msg['payload']
        if p.get('d') == 'INFO':
            print("INFO", p['msg']); return
        fh.write("%s len=%d %s\n" % (p['d'], p['len'], data.hex() if data else '')); fh.flush()
    elif msg.get('type') == 'error':
        print("JSERR", msg.get('description'))

print("launching", TARGET)
proc = subprocess.Popen([EXE, TARGET])
pid = proc.pid
# Attach ASAP (retry a few times while the process initializes).
session = None
for _ in range(40):
    try:
        session = frida.attach(pid); break
    except Exception:
        time.sleep(0.05)
if session is None:
    print("could not attach to", pid); sys.exit(1)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print("attached to", pid, "; capturing", SECS, "s ...")
time.sleep(SECS)
try: proc.kill()
except Exception as e: print("kill err", e)
fh.close()
print("done ->", OUT)
