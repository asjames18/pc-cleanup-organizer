# Local self-test (Windows). Destructive steps touch ONLY the test-sandbox folder next to the app.
import os, sys, time, json, importlib.machinery, importlib.util, shutil, subprocess
APP = os.path.dirname(os.path.abspath(__file__))
ld = importlib.machinery.SourceFileLoader("cl", os.path.join(APP, "cleanup.pyw"))
spec = importlib.util.spec_from_loader("cl", ld); cl = importlib.util.module_from_spec(spec); ld.exec_module(cl)
R = []
def check(c, m):
    R.append((bool(c), m)); print(("PASS " if c else "FAIL ") + m)
SB = os.path.join(APP, "test-sandbox")
shutil.rmtree(SB, ignore_errors=True)
org = os.path.join(SB, "organize"); dup = os.path.join(SB, "dups")
os.makedirs(org); os.makedirs(dup); os.makedirs(os.path.join(org, "Images")); os.makedirs(os.path.join(org, "Keep me"))
for n in ["IMG_0001.jpg", "invoice.pdf", "notes.docx", "budget.xlsx", "setup.msi", "clip.mp4", "song.mp3", "tool.py", "bundle.zip", "mystery.abc", "VPN.lnk", "desktop.ini"]:
    open(os.path.join(org, n), "wb").write(b"sandbox " + n.encode())
open(os.path.join(org, "Images", "IMG_0001.jpg"), "wb").write(b"existing")
open(os.path.join(org, "Keep me", "inner.txt"), "wb").write(b"x")
locked = open(os.path.join(org, "open-report.pdf"), "wb"); locked.write(b"open")  # held open = locked
blob = os.urandom(300 * 1024)
for n in ("sandbox-dup-A.bin", "sandbox-dup-B.bin"):
    open(os.path.join(dup, n), "wb").write(blob)
print("paths:", json.dumps({"home": cl.HOME, "downloads": cl.DOWNLOADS, "desktop": cl.DESKTOP, "documents": cl.DOCUMENTS, "temp": cl.TEMP_DIR}))
# allowlist on real Windows paths
check(not cl.user_path_ok(r"C:\Windows\System32\drivers\etc\hosts"), "C:\\Windows blocked")
check(not cl.user_path_ok(r"C:\Program Files\x.txt") and not cl.user_path_ok(r"C:\ProgramData\x"), "Program Files / ProgramData blocked")
check(not cl.user_path_ok(os.path.join(cl.HOME, "AppData", "Local", "x")), "AppData blocked")
check(not cl.user_path_ok(os.path.join(cl.AGENT_DIR, "todo-app", "todo.pyw")), "app parent folder (sibling apps) blocked")
check(not cl.user_path_ok("C:\\"), "drive root blocked")
check(cl.user_path_ok(os.path.join(SB, "x")), "test-sandbox allowed")
check(cl.user_path_ok(os.path.join(cl.DOWNLOADS, "x")) and cl.user_path_ok(os.path.join(cl.DESKTOP, "x")), "Downloads/Desktop allowed")
# organize -> apply -> undo
before = sorted(os.listdir(org))
plan = cl.organize_plan(org, "type", True)
to = {i["name"]: i["to"] for i in plan["items"]}
check(to.get("IMG_0001.jpg") == r"Images\IMG_0001 (1).jpg", "collision -> 'IMG_0001 (1).jpg'")
check("VPN.lnk" not in to and "desktop.ini" not in to and "Keep me" not in to, ".lnk/desktop.ini skipped, subfolders stay")
res = cl.organize_apply(org, "type", True, [i["name"] for i in plan["items"]])
fails = {f["name"]: f["reason"] for f in res["failed"]}
print("organize:", res["moved"], "moved; failed:", fails)
check(res["moved"] == len(plan["items"]) - 1 and "open-report.pdf" in fails, "moved all but the open (locked) file")
check(os.path.exists(os.path.join(org, "PDFs", "invoice.pdf")) and open(os.path.join(org, "Images", "IMG_0001.jpg"), "rb").read() == b"existing", "files in type folders, existing file kept")
u = cl.organize_undo()
check(u["restored"] == res["moved"] and sorted(os.listdir(org)) == before, "undo put everything back and removed new folders")
locked.close()
# sandbox scan + recycle-bin delete of one duplicate
st = cl.scan_job(cl.Job("scan"), SB, 100 * 1024)
g = cl.SCAN["result"]["dups"]
check(len(g) == 1 and len(g[0]["files"]) == 2, "sandbox duplicate pair found by hash")
rb0 = cl.recycle_bin_info(); check(rb0["ok"], f"SHQueryRecycleBin works ({rb0['items']} items, {cl.fmt(rb0['size'])})")
try:
    cl.recycle_files([f["path"] for f in g[0]["files"]]); check(False, "keep-one rule")
except ValueError:
    check(True, "refuses to recycle both copies")
target = os.path.join(dup, "sandbox-dup-B.bin")
r = cl.recycle_files([target])
check(r["ok"] == [target] and not os.path.exists(target) and os.path.exists(os.path.join(dup, "sandbox-dup-A.bin")), "dup B sent via SHFileOperation, A kept")
ps = "(New-Object -ComObject Shell.Application).NameSpace(10).Items() | Where-Object { $_.Name -like 'sandbox-dup-B*' } | ForEach-Object { $_.Name + ' | ' + $_.ExtendedProperty('System.Recycle.DeletedFrom') }"
out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True).stdout.strip()
print("recycle bin entry:", out)
check("sandbox-dup-B" in out and "test-sandbox" in out, "file is in the Recycle Bin (restorable)")
rb1 = cl.recycle_bin_info(); check(rb1["items"] == rb0["items"] + 1, "Recycle Bin item count +1")
check(cl.recycle_files([r"C:\Windows\notepad.exe"])["refused"], "refuses a file outside scan results / protected")
# misc
d = cl.drives(); print("drives:", [(x["root"], x["label"], cl.fmt(x["free"]), cl.fmt(x["total"])) for x in d]); check(d, "drives listed")
print("edge running:", cl.browser_running("msedge.exe"), "| chrome running:", cl.browser_running("chrome.exe"))
print("\nRESULT", sum(1 for x in R if x[0]), "/", len(R), "passed")
