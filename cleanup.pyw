"""PC Cleanup & Organizer v3: a local Windows cleanup, protection, startup, uninstall and monitoring app.
Runs a tiny private server on this PC (127.0.0.1 only) and opens the app in its own
Microsoft Edge window. Scans are read-only. Nothing is deleted or moved until you confirm it in the app.
Stdlib only, no installs."""
import json, os, sys, time, threading, subprocess, webbrowser, hashlib, heapq, tempfile, uuid, re, ctypes, fnmatch
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

IS_WIN = os.name == "nt"
VERSION = "3.1.0"
APP_DIR = os.path.dirname(os.path.abspath(__file__))


def _installed():
    """app\\installed.json is written by the installer (Install-PCCleanup.cmd); None in a plain source folder."""
    try:
        with open(os.path.join(APP_DIR, "installed.json"), "r", encoding="utf-8-sig") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return None


INSTALLED = _installed()
# Installed: %LOCALAPPDATA%\\PCCleanup\\app (code) + data (settings, logs, undo history, backups). Source folder: next to the code.
if os.environ.get("CLEANUP_DATA_DIR"):
    DATA_DIR = os.environ["CLEANUP_DATA_DIR"]
elif INSTALLED is not None:
    DATA_DIR = os.path.normpath(os.path.join(APP_DIR, INSTALLED.get("data_dir") or os.path.join("..", "data")))
else:
    DATA_DIR = APP_DIR
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except OSError:
    pass
PORT = int(os.environ.get("CLEANUP_PORT", "48251"))
NO_WINDOW = os.environ.get("CLEANUP_NO_WINDOW") == "1"
URL = f"http://127.0.0.1:{PORT}/"
VIEWS = ("dashboard", "scan", "cleanup", "organize", "apps", "protection", "startup", "monitor", "activity", "shortcuts", "settings")
_view = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--view=")), "")
APP_URL = URL + ("#" + _view if _view in VIEWS else "")
NO_WINDOW_FLAG = getattr(subprocess, "CREATE_NO_WINDOW", 0)
IDLE_LIMIT = 150
_last_ping = [time.time()]

LOG_DIR = os.path.join(DATA_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "actions.log")
UNDO_FILE = os.path.join(DATA_DIR, "undo-history.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
SANDBOX = os.path.join(DATA_DIR, "test-sandbox")
SCAN_SUMMARY_FILE = os.path.join(DATA_DIR, "scan-summary.json")
_lock = threading.RLock()

# Windows file attributes
A_READONLY, A_HIDDEN, A_SYSTEM = 0x1, 0x2, 0x4
A_REPARSE, A_OFFLINE, A_RECALL_OPEN, A_RECALL_DATA = 0x400, 0x1000, 0x40000, 0x400000
CLOUD_FILE = A_OFFLINE | A_RECALL_DATA


def known_folder(guid, fallback):
    if IS_WIN:
        try:
            class GUID(ctypes.Structure):
                _fields_ = [("a", ctypes.c_uint32), ("b", ctypes.c_uint16), ("c", ctypes.c_uint16), ("d", ctypes.c_ubyte * 8)]
            g = GUID()
            ctypes.oledll.ole32.CLSIDFromString(ctypes.c_wchar_p(guid), ctypes.byref(g))
            p = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(p)) == 0:
                v = p.value
                ctypes.windll.ole32.CoTaskMemFree(p)
                if v:
                    return v
        except Exception:
            pass
    return fallback


HOME = os.environ.get("CLEANUP_PROFILE") or os.path.expanduser("~")
LOCALAPPDATA = os.environ.get("CLEANUP_LOCALAPPDATA") or os.environ.get("LOCALAPPDATA") or os.path.join(HOME, "AppData", "Local")
TEMP_DIR = os.environ.get("CLEANUP_TEMP") or tempfile.gettempdir()
DOWNLOADS = os.environ.get("CLEANUP_DOWNLOADS") or known_folder("{374DE290-123F-4565-9164-39C4925E467B}", os.path.join(HOME, "Downloads"))
DESKTOP = os.environ.get("CLEANUP_DESKTOP") or known_folder("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", os.path.join(HOME, "Desktop"))
DOCUMENTS = os.environ.get("CLEANUP_DOCUMENTS") or known_folder("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", os.path.join(HOME, "Documents"))
AGENT_DIR = os.environ.get("CLEANUP_AGENT_DIR") or os.path.dirname(APP_DIR)


def norm(p):
    return os.path.normcase(os.path.realpath(os.path.abspath(p)))


def under(p, root):
    """p and root must already be norm()'d."""
    root = root.rstrip("\\/")
    return p == root or p.startswith(root + os.sep)


def _protected_roots():
    roots = []
    if IS_WIN:
        for k in ("SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "APPDATA", "LOCALAPPDATA"):
            v = os.environ.get(k)
            if v:
                roots.append(v)
        roots.append(os.path.join(HOME, "AppData"))
    roots += [LOCALAPPDATA, AGENT_DIR]
    roots += [p for p in os.environ.get("CLEANUP_PROTECTED", "").split(os.pathsep) if p]
    return [norm(r) for r in roots]


PROTECTED = _protected_roots()
ALLOWED_ROOTS = [norm(p) for p in (HOME, DESKTOP, DOCUMENTS, DOWNLOADS)]
SANDBOX_N = norm(SANDBOX)


TOOL_DIRS = {"node_modules", "site-packages", "__pycache__"}


def has_dot_folder(p):
    """App/tool folders like .vscode, .git, .cursor, .venv: deleting inside them can break software."""
    parts = re.split(r"[\\/]+", p)
    return any((x.startswith(".") and x not in (".", "..")) or x.lower() in TOOL_DIRS for x in parts[:-1])


def is_protected(path):
    """True for Windows, Program Files, ProgramData, AppData, the folder this app sits in (its sibling apps) (except the
    test sandbox), dot-folders like .vscode/.git, and drive roots."""
    rp = norm(path)
    if under(rp, SANDBOX_N):
        return False
    if os.path.dirname(rp) == rp:  # a drive root
        return True
    if has_dot_folder(rp):
        return True
    for r in PROTECTED:
        if under(rp, r):
            return True
    return False


def key(p):
    """Cheap identity for result sets (no disk access)."""
    return os.path.normcase(os.path.abspath(p))


def fast_protected(d):
    """Cheap per-folder check used while walking (the walk never follows links, so no realpath needed)."""
    nd = os.path.normcase(os.path.abspath(d))
    if under(nd, SANDBOX_N):
        return False
    return has_dot_folder(nd + os.sep) or any(under(nd, r) for r in PROTECTED)


def user_path_ok(path):
    """Server-side allowlist for anything that moves or recycles user files."""
    if not path or not os.path.isabs(path):
        return False
    rp = norm(path)
    if is_protected(rp):
        return False
    if under(rp, SANDBOX_N):
        return True
    return any(under(rp, r) for r in ALLOWED_ROOTS)


def attrs_of(st):
    return getattr(st, "st_file_attributes", 0)


def is_cloud(st):
    return bool(attrs_of(st) & CLOUD_FILE)


def skip_dir_entry(e, st):
    """Skip symlinks, junctions and other reparse points, but keep OneDrive cloud folders."""
    if e.is_symlink():
        return True
    if getattr(e, "is_junction", lambda: False)():
        return True
    if attrs_of(st) & A_REPARSE:
        tag = getattr(st, "st_reparse_tag", 0)
        if (tag & 0xFFFF0FFF) != 0x9000001A:  # IO_REPARSE_TAG_CLOUD_*
            return True
    return False


def fmt(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return (f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}")
        n /= 1024


# ---------------------------------------------------------------- logging, settings, undo
def log_action(kind, msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {kind} | {msg}\n"
    with _lock:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)


def read_log(limit=400):
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for ln in reversed(lines):
        parts = ln.rstrip("\n").split(" | ", 2)
        if len(parts) == 3:
            out.append({"time": parts[0], "kind": parts[1], "msg": parts[2]})
    return out


DEFAULT_SETTINGS = {"old_days": 90, "dup_min_kb": 100, "skip_links": True, "rule": "type", "last_scan": "", "saved_rules": []}


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:  # tolerate a byte-order mark
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    with _lock:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)


def load_settings():
    s = dict(DEFAULT_SETTINGS)
    d = load_json(SETTINGS_FILE, {})
    if isinstance(d, dict):
        s.update({k: v for k, v in d.items() if k in DEFAULT_SETTINGS})
    return s


def load_undo():
    d = load_json(UNDO_FILE, [])
    return d if isinstance(d, list) else []


# ---------------------------------------------------------------- jobs
class Job:
    def __init__(self, kind):
        self.id = uuid.uuid4().hex[:10]
        self.kind = kind
        self.cancel = threading.Event()
        self.progress = {"phase": "starting"}
        self.result = None
        self.error = None
        self.done = False
        self.started = time.time()
        self.ended = None

    def view(self, with_result=True):
        return {"id": self.id, "kind": self.kind, "done": self.done, "cancelled": self.cancel.is_set(),
                "error": self.error, "progress": self.progress, "elapsed": round((self.ended or time.time()) - self.started, 1),
                "result": self.result if (with_result and self.done) else None}


JOBS, CURRENT = {}, {}


def start_job(kind, fn, *args):
    with _lock:
        cur = CURRENT.get(kind)
        if cur and not cur.done:
            return cur
        job = Job(kind)
        JOBS[job.id] = job
        CURRENT[kind] = job

    def run():
        try:
            job.result = fn(job, *args)
        except Exception as e:  # report, never crash the server
            job.error = str(e)
            log_action("ERROR", f"{kind}: {e}")
        finally:
            job.ended = time.time()
            job.done = True
    threading.Thread(target=run, daemon=True).start()
    return job


def any_job_running():
    return any(not j.done for j in CURRENT.values())


# ---------------------------------------------------------------- drives
def drives():
    out = []
    if IS_WIN:
        try:
            mask = ctypes.windll.kernel32.GetLogicalDrives()
        except Exception:
            mask = 0
        for i in range(26):
            if not mask & (1 << i):
                continue
            root = chr(65 + i) + ":\\"
            t = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
            if t not in (2, 3):  # removable, fixed (skip network/optical so nothing hangs)
                continue
            try:
                total, free = _disk(root)
            except OSError:
                continue
            label = ctypes.create_unicode_buffer(261)
            ctypes.windll.kernel32.GetVolumeInformationW(ctypes.c_wchar_p(root), label, 261, None, None, None, None, 0)
            out.append({"root": root, "label": label.value or ("Local Disk" if t == 3 else "Removable"), "total": total, "free": free, "used": total - free})
    else:
        total, free = _disk("/")
        out.append({"root": "/", "label": "Root", "total": total, "free": free, "used": total - free})
    return out


def _disk(root):
    import shutil
    u = shutil.disk_usage(root)
    return u.total, u.free


# ---------------------------------------------------------------- scan (read-only)
SCAN = {"result": None}
TOP_N = 100


def scan_job(job, root, dup_min):
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise ValueError("That folder doesn't exist")
    t0 = time.time()
    p = job.progress
    p.update(phase="walk", files=0, dirs=0, bytes=0, cloud=0, errors=0, links=0, current=root, hashed=0, hash_total=0)
    dirs, order = {}, []
    heap, counter = [], 0
    by_size = {}
    dl_n = os.path.normcase(os.path.abspath(DOWNLOADS))
    root_n = os.path.normcase(root)
    dl_inside = under(root_n, dl_n) or under(dl_n, root_n)
    downloads = []
    stack = [(root, None)]
    last = 0

    def walk_one(d, parent, collect=True):
        nonlocal counter, last
        node = {"s": 0, "f": 0, "c": 0, "k": [], "p": parent, "x": 0}
        if collect:
            dirs[d] = node
            order.append(d)
            if parent is not None:
                dirs[parent]["k"].append(d)
        sub = []
        in_dl = (dl_inside or not collect) and under(os.path.normcase(d), dl_n)
        prot = fast_protected(d)
        try:
            it = os.scandir(d)
        except OSError:
            p["errors"] += 1
            node["x"] = 1
            return sub
        with it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                    if e.is_symlink():
                        p["links"] += 1
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if skip_dir_entry(e, st):
                            p["links"] += 1
                        else:
                            sub.append(e.path)
                        continue
                    if not e.is_file(follow_symlinks=False):
                        continue
                except OSError:
                    p["errors"] += 1
                    continue
                size, cloud = st.st_size, is_cloud(st)
                if collect:
                    node["f"] += 1
                    p["files"] += 1
                    if cloud:
                        node["c"] += size
                        p["cloud"] += size
                    else:
                        node["s"] += size
                        p["bytes"] += size
                    counter += 1
                    item = (size, counter, e.path, st.st_mtime, cloud)
                    if len(heap) < TOP_N:
                        heapq.heappush(heap, item)
                    elif size > heap[0][0]:
                        heapq.heapreplace(heap, item)
                    if not cloud and not prot and size >= dup_min:
                        by_size.setdefault(size, []).append((e.path, st.st_mtime))
                if in_dl and size >= OLD_MIN:
                    downloads.append((e.path, size, st.st_mtime, cloud, prot))
        if collect:
            p["dirs"] += 1
            now = time.time()
            if now - last > 0.15:
                p["current"] = d
                last = now
        return sub

    while stack:
        if job.cancel.is_set():
            return None
        d, parent = stack.pop()
        for s in walk_one(d, parent):
            stack.append((s, d))
    if not dl_inside and os.path.isdir(DOWNLOADS):
        walk_one(DOWNLOADS, None, collect=False)  # top-level files only when Downloads is outside the scan

    # roll sizes up (children were discovered after their parents)
    for d in reversed(order):
        n = dirs[d]
        n["ts"], n["tf"], n["tc"] = n["s"], n["f"], n["c"]
        for k in n["k"]:
            c = dirs[k]
            n["ts"] += c["ts"]; n["tf"] += c["tf"]; n["tc"] += c["tc"]

    # duplicates: same size -> partial hash -> full hash
    p["phase"] = "hash"
    cands = sorted(((s, v) for s, v in by_size.items() if len(v) > 1), key=lambda x: -x[0])
    p["hash_total"] = sum(s * len(v) for s, v in cands)
    p["dup_candidates"] = sum(len(v) for _, v in cands)
    groups = []
    for size, files in cands:
        if job.cancel.is_set():
            return None
        part = {}
        for path, mt in files:
            h = file_hash(path, size, partial=True, job=job)
            if h:
                part.setdefault(h, []).append((path, mt))
        for same in part.values():
            if len(same) < 2:
                continue
            if size <= 2 * PART:
                full = {"p": same}
            else:
                full = {}
                for path, mt in same:
                    h = file_hash(path, size, partial=False, job=job)
                    if h:
                        full.setdefault(h, []).append((path, mt))
                    if job.cancel.is_set():
                        return None
            for h, g in full.items():
                if len(g) > 1:
                    groups.append({"size": size, "files": [{"path": a, "mtime": m} for a, m in sorted(g, key=lambda x: x[1])]})
        p["current"] = files[0][0]
    groups.sort(key=lambda g: -g["size"] * (len(g["files"]) - 1))
    groups = groups[:300]

    largest = [{"path": x[2], "size": x[0], "mtime": x[3], "cloud": x[4], "protected": is_protected(x[2])}
               for x in sorted(heap, key=lambda x: -x[0])]
    for g in groups:
        for f in g["files"]:
            f["protected"] = is_protected(f["path"])
    dl = [{"path": a, "size": s, "mtime": m, "cloud": c, "protected": pr} for a, s, m, c, pr in downloads]
    deletable = set()
    for lst in (largest, dl):
        deletable.update(key(x["path"]) for x in lst if not x["cloud"] and not x["protected"])
    dup_index = {}
    for gi, g in enumerate(groups):
        for f in g["files"]:
            if not f["protected"]:
                deletable.add(key(f["path"]))
            dup_index[key(f["path"])] = gi
    rn = dirs[root]
    stats = {"root": root, "size": rn["ts"], "files": rn["tf"], "cloud": rn["tc"], "dirs": len(dirs), "errors": p["errors"],
             "links": p["links"], "seconds": round(time.time() - t0, 1), "finished": time.strftime("%Y-%m-%d %H:%M"),
             "dup_groups": len(groups), "dup_waste": sum(g["size"] * (len(g["files"]) - 1) for g in groups),
             "downloads": DOWNLOADS, "downloads_files": len(dl), "downloads_recursive": dl_inside}
    with _lock:
        SCAN["result"] = {"dirs": dirs, "largest": largest, "dups": groups, "downloads": dl, "stats": stats,
                          "deletable": deletable, "dup_index": dup_index, "root": root}
    s = load_settings(); s["last_scan"] = root; save_json(SETTINGS_FILE, s)
    try:
        save_json(SCAN_SUMMARY_FILE, scan_summary(s.get("old_days", 90)))
    except Exception:
        pass
    log_action("SCAN", f"Read-only scan of {root}: {fmt(stats['size'])} in {stats['files']:,} files "
                       f"({fmt(stats['cloud'])} cloud-only), {len(groups)} duplicate sets, {stats['seconds']}s")
    return stats


PART = 64 * 1024
OLD_MIN = 64 * 1024  # old-downloads list ignores tiny files


def file_hash(path, size, partial, job=None):
    try:
        if is_cloud(os.stat(path, follow_symlinks=False)):
            return None  # never hydrate OneDrive placeholders
        h = hashlib.blake2b(digest_size=20)
        with open(path, "rb") as f:
            if partial:
                h.update(f.read(PART))
                if size > 2 * PART:
                    f.seek(size - PART)
                    h.update(f.read(PART))
                if job:
                    job.progress["hashed"] += min(size, 2 * PART)
            else:
                while True:
                    b = f.read(1024 * 1024)
                    if not b:
                        break
                    h.update(b)
                    if job:
                        job.progress["hashed"] += len(b)
                        if job.cancel.is_set():
                            return None
        return h.hexdigest()
    except OSError:
        return None


def scan_summary(old_days=90):
    """Compact, file-name-only summary of the last scan (no file contents), kept on disk so recommendations work after a restart."""
    r = SCAN["result"]
    if not r:
        return None
    groups = []
    for g in r["dups"][:15]:
        fs = [f for f in g["files"]]
        groups.append({"name": os.path.basename(fs[0]["path"]), "copies": len(fs), "size": g["size"], "waste": g["size"] * (len(fs) - 1),
                       "paths": [f["path"] for f in fs][:4], "protected": sum(1 for f in fs if f.get("protected"))})
    od = old_downloads(old_days) or {}
    return {"time": r["stats"]["finished"], "root": r["root"], "dup_groups": len(r["dups"]),
            "dup_waste": sum(g["size"] * (len(g["files"]) - 1) for g in r["dups"]), "dup_top": groups,
            "old_days": old_days, "old_count": od.get("count", 0), "old_size": od.get("size", 0),
            "downloads_recursive": r["stats"].get("downloads_recursive")}


def scan_dir_view(path=None):
    r = SCAN["result"]
    if not r:
        return None
    path = path or r["root"]
    n = r["dirs"].get(path)
    if n is None:
        return None
    kids = sorted(({"name": os.path.basename(k) or k, "path": k, "size": r["dirs"][k]["ts"], "files": r["dirs"][k]["tf"],
                    "cloud": r["dirs"][k]["tc"], "denied": r["dirs"][k]["x"], "has_kids": bool(r["dirs"][k]["k"])} for k in n["k"]),
                  key=lambda x: -(x["size"] + x["cloud"]))
    crumbs, q = [], path
    while q is not None:
        crumbs.append({"name": os.path.basename(q) or q, "path": q})
        q = r["dirs"][q]["p"]
    return {"path": path, "size": n["ts"], "files": n["tf"], "cloud": n["tc"], "own": {"size": n["s"], "files": n["f"], "cloud": n["c"]},
            "children": kids[:80], "more": max(0, len(kids) - 80), "crumbs": list(reversed(crumbs))}


def old_downloads(days):
    r = SCAN["result"]
    if not r:
        return None
    cut = time.time() - days * 86400
    items = sorted((x for x in r["downloads"] if x["mtime"] < cut), key=lambda x: -x["size"])
    return {"days": days, "count": len(items), "size": sum(x["size"] for x in items if not x["cloud"]), "items": items[:500],
            "folder": DOWNLOADS}


# ---------------------------------------------------------------- recycle bin helpers (Windows shell)
class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint32), ("i64Size", ctypes.c_int64), ("i64NumItems", ctypes.c_int64)]


def recycle_bin_info():
    if not IS_WIN:
        tb = os.environ.get("CLEANUP_FAKE_TRASH")
        if tb and os.path.isdir(tb):
            fs = [os.path.join(tb, f) for f in os.listdir(tb)]
            return {"ok": True, "size": sum(os.path.getsize(f) for f in fs if os.path.isfile(f)), "items": len(fs)}
        return {"ok": False, "size": 0, "items": 0}
    info = SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(info)
    hr = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
    return {"ok": hr == 0, "size": info.i64Size, "items": info.i64NumItems}


def empty_recycle_bin():
    if not IS_WIN:
        tb = os.environ.get("CLEANUP_FAKE_TRASH")
        for f in os.listdir(tb):
            os.remove(os.path.join(tb, f))
        return True
    hr = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x1 | 0x2 | 0x4)  # no confirm/progress/sound
    return hr == 0 or hr == -2147418113  # E_UNEXPECTED = already empty


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [("hwnd", ctypes.c_void_p), ("wFunc", ctypes.c_uint), ("pFrom", ctypes.c_wchar_p), ("pTo", ctypes.c_wchar_p),
                ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", ctypes.c_int), ("hNameMappings", ctypes.c_void_p),
                ("lpszProgressTitle", ctypes.c_wchar_p)]


FO_DELETE, FOF_SILENT, FOF_NOCONFIRMATION, FOF_ALLOWUNDO, FOF_NOERRORUI, FOF_WANTNUKEWARNING = 3, 0x4, 0x10, 0x40, 0x400, 0x4000


def send_to_recycle_bin(path):
    """Move one file to the Recycle Bin (undoable). If Windows can't recycle it, it asks before deleting for good."""
    if not IS_WIN:
        tb = os.environ.get("CLEANUP_FAKE_TRASH")
        if not tb:
            raise OSError("no recycle bin on this OS")
        os.makedirs(tb, exist_ok=True)
        os.rename(path, os.path.join(tb, uuid.uuid4().hex[:6] + "_" + os.path.basename(path)))
        return True
    try:
        ctypes.windll.ole32.CoInitialize(None)
    except Exception:
        pass
    op = SHFILEOPSTRUCTW()
    op.wFunc = FO_DELETE
    op.pFrom = path + "\0"
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_WANTNUKEWARNING
    rc = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    return rc == 0 and not op.fAnyOperationsAborted and not os.path.exists(path)


def recycle_files(paths, dry=False):
    r = SCAN["result"]
    if not r:
        raise ValueError("Run a scan first")
    ok, failed, freed, refused = [], [], 0, []
    # keep at least one copy of every duplicate set
    by_group = {}
    for pth in paths:
        gi = r["dup_index"].get(key(pth))
        if gi is not None:
            by_group.setdefault(gi, set()).add(key(pth))
    for gi, sel in by_group.items():
        allf = {key(f["path"]) for f in r["dups"][gi]["files"]}
        if allf <= sel:
            raise ValueError("That would remove every copy of a duplicate set. Keep at least one.")
    for pth in paths:
        n = key(pth)
        reason = None
        if n not in r["deletable"]:
            reason = "not part of the last scan's results"
        elif not user_path_ok(pth):
            reason = "protected location"
        else:
            try:
                st = os.stat(pth, follow_symlinks=False)
                if is_cloud(st):
                    reason = "cloud-only OneDrive file"
                elif attrs_of(st) & A_SYSTEM:
                    reason = "system file"
                elif not os.path.isfile(pth) or os.path.islink(pth):
                    reason = "not a regular file"
            except OSError:
                reason = "missing"
        if reason:
            refused.append({"path": pth, "reason": reason})
            continue
        size = os.path.getsize(pth)
        if dry:
            ok.append(pth); freed += size
            continue
        try:
            if send_to_recycle_bin(pth):
                ok.append(pth); freed += size
                r["deletable"].discard(n)
                log_action("RECYCLE", f"Sent to Recycle Bin: {pth} ({fmt(size)})")
            else:
                failed.append({"path": pth, "reason": "in use or cancelled"})
        except OSError as e:
            failed.append({"path": pth, "reason": str(e)})
    if not dry:
        _drop_from_results(set(key(x) for x in ok))
        log_action("RECYCLE", f"{len(ok)} file(s) to Recycle Bin, {fmt(freed)}; {len(failed)} failed, {len(refused)} refused")
    else:
        log_action("DRY RUN", f"Recycle preview: {len(ok)} file(s), {fmt(freed)}; {len(refused)} refused")
    return {"ok": ok, "failed": failed, "refused": refused, "freed": freed, "dry": dry}


def _drop_from_results(gone):
    r = SCAN["result"]
    r["largest"] = [x for x in r["largest"] if key(x["path"]) not in gone]
    r["downloads"] = [x for x in r["downloads"] if key(x["path"]) not in gone]
    for g in r["dups"]:
        g["files"] = [f for f in g["files"] if key(f["path"]) not in gone]
    r["dups"] = [g for g in r["dups"] if len(g["files"]) > 1]
    r["dup_index"] = {key(f["path"]): gi for gi, g in enumerate(r["dups"]) for f in g["files"]}


# ---------------------------------------------------------------- cleanup categories
CACHE_DIRS = ("Cache", "Code Cache", "GPUCache")
INSTALLER_EXT = (".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle")
LOG_PATTERNS = ("*.log", "*.log.[0-9]*", "*.etl", "*.old.log")


def browser_cache_roots(user_data):
    out = []
    try:
        names = os.listdir(user_data)
    except OSError:
        return out
    for name in names:
        if not (name == "Default" or name.startswith("Profile ") or name == "Guest Profile"):
            continue
        for sub in CACHE_DIRS:
            q = os.path.join(user_data, name, sub)
            if os.path.isdir(q) and not os.path.islink(q):
                out.append(q)
    return out


def firefox_cache_roots():
    base = os.path.join(LOCALAPPDATA, "Mozilla", "Firefox", "Profiles")
    try:
        return [os.path.join(base, n, "cache2") for n in os.listdir(base) if os.path.isdir(os.path.join(base, n, "cache2"))]
    except OSError:
        return []


def roaming_dir():
    return os.environ.get("CLEANUP_APPDATA") or os.environ.get("APPDATA") or os.path.join(HOME, "AppData", "Roaming")


def log_dirs(max_depth=3):
    """Folders literally named logs/log under LocalAppData and Roaming (depth <= 3). Temp and Packages are skipped."""
    out = []
    for base in (LOCALAPPDATA, roaming_dir()):
        stack = [(base, 0)]
        while stack:
            d, depth = stack.pop()
            try:
                it = list(os.scandir(d))
            except OSError:
                continue
            for e in it:
                try:
                    if not e.is_dir(follow_symlinks=False) or e.is_symlink():
                        continue
                except OSError:
                    continue
                nl = e.name.lower()
                if depth == 0 and nl in ("temp", "packages", "microsoft", "crashdumps"):
                    continue
                if nl in ("logs", "log"):
                    out.append(e.path)
                elif depth + 1 < max_depth:
                    stack.append((e.path, depth + 1))
    return out[:400]


def _fixed(*parts_list):
    return [os.path.join(*p) for p in parts_list]


def categories(with_logs=True):
    edge = os.path.join(LOCALAPPDATA, "Microsoft", "Edge", "User Data")
    chrome = os.path.join(LOCALAPPDATA, "Google", "Chrome", "User Data")
    win = os.environ.get("SystemRoot") or r"C:\Windows"
    pdata = os.environ.get("ProgramData") or r"C:\ProgramData"
    L = LOCALAPPDATA
    return [
        {"id": "temp", "name": "Temporary files", "desc": "Your user TEMP folder. Files changed in the last 24 hours are kept.",
         "roots": [TEMP_DIR], "min_age": 86400, "default": True, "exe": None, "group": "clean"},
        {"id": "edge", "name": "Microsoft Edge cache", "desc": "Cache, Code Cache and GPUCache only. Cookies, history, passwords and profiles are never touched.",
         "roots": browser_cache_roots(edge), "min_age": 0, "default": True, "exe": "msedge.exe", "present": os.path.isdir(edge), "group": "clean"},
        {"id": "chrome", "name": "Google Chrome cache", "desc": "Cache, Code Cache and GPUCache only. Cookies, history, passwords and profiles are never touched.",
         "roots": browser_cache_roots(chrome), "min_age": 0, "default": True, "exe": "chrome.exe", "present": os.path.isdir(chrome), "group": "clean"},
        {"id": "firefox", "name": "Firefox cache", "desc": "The cache2 folder of each Firefox profile. Cookies, history and passwords are never touched.",
         "roots": firefox_cache_roots(), "min_age": 0, "default": True, "exe": "firefox.exe",
         "present": os.path.isdir(os.path.join(L, "Mozilla", "Firefox")), "group": "clean"},
        {"id": "wer", "name": "Crash dumps and error reports", "desc": "Old app crash dumps and Windows Error Reporting files for your account. Only needed if you're debugging a crash.",
         "roots": _fixed((L, "CrashDumps"), (L, "Microsoft", "Windows", "WER", "ReportArchive"), (L, "Microsoft", "Windows", "WER", "ReportQueue")),
         "fixed": True, "min_age": 86400, "default": True, "exe": None, "group": "clean"},
        {"id": "shader", "name": "Shader and DirectX caches", "desc": "DirectX, NVIDIA, AMD and Intel shader caches. They rebuild themselves; the first launch of a game may be a little slower.",
         "roots": _fixed((L, "D3DSCache"), (L, "NVIDIA", "DXCache"), (L, "NVIDIA", "GLCache"), (L, "AMD", "DxCache"), (L, "AMD", "GLCache"), (L, "Intel", "ShaderCache")),
         "fixed": True, "min_age": 0, "default": False, "exe": None, "group": "clean"},
        {"id": "thumbs", "name": "Thumbnail and icon cache", "desc": "Explorer's thumbcache_*.db and iconcache_*.db files. Windows rebuilds them. Files Explorer has open are skipped.",
         "roots": [os.path.join(L, "Microsoft", "Windows", "Explorer")], "patterns": ("thumbcache_*.db", "iconcache_*.db"), "flat": True, "fixed": True,
         "min_age": 0, "default": False, "exe": None, "group": "clean"},
        {"id": "logs", "name": "Old app log files", "desc": "*.log and *.etl files older than 30 days inside apps' logs folders (LocalAppData and Roaming). Nothing else in those folders is touched.",
         "roots": log_dirs() if with_logs else [], "patterns": LOG_PATTERNS, "min_age": 30 * 86400, "default": False, "exe": None, "group": "clean"},
        {"id": "devcache", "name": "Developer caches (npm, pip)", "desc": "Opt-in. npm and pip download caches. Safe to clear, but the next install re-downloads packages, so it will be slower once.",
         "roots": _fixed((L, "npm-cache", "_cacache"), (L, "pip", "cache")), "fixed": True, "min_age": 0, "default": False, "exe": None,
         "group": "optin", "optin": True},
        # review-only: measured, never cleaned by this app
        {"id": "wucache", "name": "Windows Update download cache", "desc": "Installer files Windows Update already used. Windows manages this folder; clean it with Settings › Storage › Temporary files.",
         "roots": _fixed((win, "SoftwareDistribution", "Download")), "fixed": True, "min_age": 0, "default": False, "exe": None, "group": "review",
         "review_only": True, "needs_admin": True, "how": "storage"},
        {"id": "delivery", "name": "Delivery Optimization cache", "desc": "Update pieces Windows shares between PCs. Clean it with Settings › Storage › Temporary files › Delivery Optimization Files.",
         "roots": _fixed((win, "ServiceProfiles", "NetworkService", "AppData", "Local", "Microsoft", "Windows", "DeliveryOptimization", "Cache"),
                         (win, "SoftwareDistribution", "DeliveryOptimization")), "fixed": True, "min_age": 0, "default": False, "exe": None, "group": "review",
         "review_only": True, "needs_admin": True, "how": "storage"},
        {"id": "nvinst", "name": "NVIDIA installer cache", "desc": "Old NVIDIA driver downloads and unpacked installers (ProgramData and C:\\NVIDIA). Remove them with admin rights once the current driver works.",
         "roots": _fixed((pdata, "NVIDIA Corporation", "Downloader"), (os.path.splitdrive(win)[0] + os.sep, "NVIDIA")), "fixed": True, "min_age": 0,
         "default": False, "exe": None, "group": "review", "review_only": True, "needs_admin": True, "how": "folder"},
    ]


def clean_ids():
    return [c["id"] for c in categories(with_logs=False) if not c.get("review_only")]


def category_root_ok(cat, root):
    """Only the exact cache/temp folders above, never anything else in AppData."""
    rn = norm(root)
    if os.path.dirname(rn) == rn:
        return False
    cid = cat["id"]
    if cid == "temp":
        sysroot = os.environ.get("SystemRoot")
        return os.path.basename(rn).lower() in ("temp", "tmp") and not (sysroot and under(rn, norm(sysroot)))
    if cid in ("wucache", "delivery", "nvinst"):  # review-only: may be measured, never cleaned
        return any(rn == norm(r) for r in next(c for c in categories(False) if c["id"] == cid)["roots"])
    if cid == "logs":
        return os.path.basename(rn).lower() in ("logs", "log") and (under(rn, norm(LOCALAPPDATA)) or under(rn, norm(roaming_dir()))) \
            and not under(rn, norm(TEMP_DIR)) and not has_dot_folder(rn + os.sep)
    if not under(rn, norm(LOCALAPPDATA)):
        return False
    if cid in ("edge", "chrome"):
        return os.path.basename(root) in CACHE_DIRS
    if cid == "firefox":
        return os.path.basename(rn) == "cache2" and under(rn, norm(os.path.join(LOCALAPPDATA, "Mozilla", "Firefox", "Profiles")))
    if cid in ("wer", "shader", "thumbs", "devcache"):
        return any(rn == norm(r) for r in next(c for c in categories(False) if c["id"] == cid)["roots"])
    return False


def category_files(cat, cancel=None, stats=None):
    """Yields (path, size). Never yields OneDrive cloud-only placeholders (they're counted in stats['cloud'] only)."""
    now = time.time()
    pats = cat.get("patterns") or ((cat["pattern"],) if cat.get("pattern") else ())
    for root in cat["roots"]:
        if not category_root_ok(cat, root):
            continue
        stack = [root]
        while stack:
            if cancel is not None and cancel.is_set():
                return
            d = stack.pop()
            try:
                it = os.scandir(d)
            except PermissionError:
                if stats is not None:
                    stats["denied"] = stats.get("denied", 0) + 1
                continue
            except OSError:
                continue
            with it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                        if e.is_dir(follow_symlinks=False):
                            if not cat.get("flat") and not skip_dir_entry(e, st):
                                stack.append(e.path)
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    if is_cloud(st):
                        if stats is not None:
                            stats["cloud"] = stats.get("cloud", 0) + 1
                        continue
                    if pats and not any(fnmatch.fnmatch(e.name.lower(), p) for p in pats):
                        continue
                    if cat["min_age"] and now - st.st_mtime < cat["min_age"]:
                        continue
                    yield e.path, st.st_size


def browser_running(exe):
    if not exe:
        return False
    if not IS_WIN:
        return exe in os.environ.get("CLEANUP_FAKE_RUNNING", "")
    ps = f"Get-CimInstance Win32_Process -Filter \"Name='{exe}'\" | ForEach-Object {{ $_.CommandLine }}"
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, text=True,
                             timeout=25, creationflags=NO_WINDOW_FLAG).stdout
    except Exception:
        return True  # can't tell: be safe
    for line in out.splitlines():
        l = line.strip().lower()
        if not l or "--type=" in l:
            continue  # helper processes
        if "--user-data-dir=" in l:
            continue  # app windows with their own profile (like this app), not the real browser
        return True
    return False


def downloads_installers(min_age_days=30, max_depth=2, limit=40):
    """Review-only: installer files (.exe/.msi/...) in Downloads older than N days. Cloud-only placeholders are never counted."""
    cut = time.time() - min_age_days * 86400
    found, cloud = [], 0
    stack = [(DOWNLOADS, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            it = list(os.scandir(d))
        except OSError:
            continue
        for e in it:
            try:
                st = e.stat(follow_symlinks=False)
                if e.is_dir(follow_symlinks=False):
                    if depth + 1 < max_depth and not skip_dir_entry(e, st) and not e.name.startswith("."):
                        stack.append((e.path, depth + 1))
                    continue
                if not e.is_file(follow_symlinks=False) or not e.name.lower().endswith(INSTALLER_EXT):
                    continue
            except OSError:
                continue
            if is_cloud(st):
                cloud += 1
                continue
            if st.st_mtime < cut:
                found.append({"path": e.path, "size": st.st_size, "mtime": st.st_mtime, "age_days": int((time.time() - st.st_mtime) / 86400)})
    found.sort(key=lambda x: -x["size"])
    return {"count": len(found), "size": sum(x["size"] for x in found), "items": found[:limit], "cloud_skipped": cloud,
            "days": min_age_days, "folder": DOWNLOADS}


def measure_job(job):
    out = []
    for cat in categories():
        if job.cancel.is_set():
            return None
        job.progress.update(phase="measure", current=cat["name"])
        n, size, stats = 0, 0, {}
        for _, s in category_files(cat, job.cancel, stats):
            n += 1; size += s
        running = browser_running(cat["exe"])
        out.append({"id": cat["id"], "name": cat["name"], "desc": cat["desc"], "files": n, "size": size, "default": cat["default"],
                    "running": running, "roots": [r for r in cat["roots"] if category_root_ok(cat, r)][:6], "nroots": len(cat["roots"]),
                    "present": cat.get("present", True), "group": cat.get("group", "clean"), "review_only": bool(cat.get("review_only")),
                    "needs_admin": bool(cat.get("needs_admin")), "optin": bool(cat.get("optin")), "how": cat.get("how", ""),
                    "denied": stats.get("denied", 0), "cloud_skipped": stats.get("cloud", 0)})
    job.progress.update(phase="measure", current="Old installers in Downloads")
    try:
        inst = downloads_installers()
    except Exception as e:
        inst = {"count": 0, "size": 0, "items": [], "error": str(e)}
    rb = recycle_bin_info()
    res = {"cats": out, "recycle": rb, "installers": inst, "time": time.strftime("%H:%M")}
    CATS["last"] = res
    return res


CATS = {"last": None}


def _skip_reason(e):
    if isinstance(e, PermissionError):
        return "in use or access denied"
    if isinstance(e, FileNotFoundError):
        return "already gone"
    return type(e).__name__


def clean_job(job, ids, dry):
    job.progress.update(phase="clean", deleted=0, freed=0, skipped=0)
    report = []
    for cat in categories():
        if cat["id"] not in ids or cat.get("review_only"):
            continue
        if browser_running(cat["exe"]):
            report.append({"id": cat["id"], "name": cat["name"], "deleted": 0, "freed": 0, "skipped": 0, "skipped_examples": [],
                           "note": f"Skipped: {cat['exe']} is running. Close the browser and try again."})
            continue
        job.progress["current"] = cat["name"]
        d = fr = sk = 0
        examples = []
        for path, size in list(category_files(cat, job.cancel)):
            if job.cancel.is_set():
                break
            if dry:
                d += 1; fr += size
                continue
            try:
                os.remove(path)
                d += 1; fr += size
                job.progress["deleted"] += 1
            except OSError as e:  # locked or in use: leave it
                if isinstance(e, FileNotFoundError):
                    continue
                sk += 1
                if len(examples) < 8:
                    examples.append({"path": path, "reason": _skip_reason(e)})
        if not dry and cat["id"] == "temp":
            _remove_empty_dirs(cat["roots"][0], 86400)
        job.progress["freed"] += fr; job.progress["skipped"] += sk
        report.append({"id": cat["id"], "name": cat["name"], "deleted": d, "freed": fr, "skipped": sk, "skipped_examples": examples, "note": ""})
        log_action("DRY RUN" if dry else "CLEAN", f"{cat['name']}: {'would delete' if dry else 'deleted'} {d:,} files, "
                                                   f"{fmt(fr)}; {sk:,} locked/skipped")
    return {"dry": dry, "report": report, "freed": sum(x["freed"] for x in report), "deleted": sum(x["deleted"] for x in report),
            "skipped": sum(x["skipped"] for x in report), "cancelled": job.cancel.is_set()}


def _remove_empty_dirs(root, min_age):
    now = time.time()
    for d, subs, files in os.walk(root, topdown=False):
        if d == root or os.path.islink(d):
            continue
        try:
            if not os.listdir(d) and now - os.stat(d).st_mtime > min_age:
                os.rmdir(d)
        except OSError:
            pass


TYPES = [
    ("Images", "jpg jpeg png gif bmp webp heic heif tif tiff svg ico raw cr2 nef psd avif"),
    ("PDFs", "pdf"),
    ("Documents", "doc docx docm odt rtf txt md ppt pptx pptm odp one vsdx pages key epub"),
    ("Spreadsheets", "xls xlsx xlsm xlsb csv tsv ods numbers"),
    ("Archives", "zip rar 7z tar gz tgz bz2 xz iso cab"),
    ("Installers", "exe msi msix msixbundle appx appxbundle dmg pkg"),
    ("Video", "mp4 mkv mov avi wmv webm m4v flv mpg mpeg"),
    ("Audio", "mp3 wav m4a aac flac ogg wma opus"),
    ("Code", "py pyw js mjs ts tsx jsx json html htm css ps1 psm1 bat cmd sh java c cpp h cs go rb php sql xml yml yaml ipynb toml ini cfg"),
]
EXT_TYPE = {e: name for name, exts in TYPES for e in exts.split()}
TYPE_NAMES = [n for n, _ in TYPES] + ["Other"]
PARTIAL_EXT = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload")


def validate_folder(folder):
    if not folder or not os.path.isabs(folder) or not os.path.isdir(folder):
        raise ValueError("Pick an existing folder")
    if not user_path_ok(folder):
        raise ValueError("That folder is protected. Pick a folder inside your user profile, like Downloads, Desktop or Documents.")
    return os.path.abspath(folder)


def _target_group(name, mtime, rule):
    if rule == "date":
        t = time.localtime(mtime)
        return os.path.join(f"{t.tm_year:04d}", f"{t.tm_mon:02d}")
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    return EXT_TYPE.get(ext, "Other")


def unique_name(dest_dir, name, taken):
    base, ext = os.path.splitext(name)
    cand, i = name, 1
    while os.path.lexists(os.path.join(dest_dir, cand)) or os.path.normcase(os.path.join(dest_dir, cand)) in taken:
        cand = f"{base} ({i}){ext}"
        i += 1
    return cand


def organize_plan(folder, rule="type", skip_links=True):
    folder = validate_folder(folder)
    if rule not in ("type", "date"):
        raise ValueError("bad rule")
    items, skipped, taken = [], [], set()
    try:
        entries = sorted(os.scandir(folder), key=lambda e: e.name.lower())
    except OSError as e:
        raise ValueError(f"Can't read that folder: {e}")
    for e in entries:
        try:
            if e.is_symlink() or not e.is_file(follow_symlinks=False):
                continue  # only top-level files; subfolders stay put
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        name, low = e.name, e.name.lower()
        a = attrs_of(st)
        why = None
        if low == "desktop.ini" or a & (A_HIDDEN | A_SYSTEM) or name.startswith("."):
            why = "hidden or system file"
        elif skip_links and low.endswith((".lnk", ".url")):
            why = "shortcut (toggle to include)"
        elif low.endswith(PARTIAL_EXT):
            why = "download in progress"
        elif name.startswith("~$"):
            why = "Office lock file (document is open)"
        if why:
            skipped.append({"name": name, "reason": why})
            continue
        group = _target_group(name, st.st_mtime, rule)
        dest_dir = os.path.join(folder, group)
        final = unique_name(dest_dir, name, taken)
        taken.add(os.path.normcase(os.path.join(dest_dir, final)))
        items.append({"name": name, "group": group, "to": os.path.join(group, final), "renamed": final != name,
                      "size": st.st_size, "cloud": is_cloud(st)})
    counts = {}
    for it in items:
        counts[it["group"]] = counts.get(it["group"], 0) + 1
    return {"folder": folder, "rule": rule, "skip_links": skip_links, "items": items, "skipped": skipped,
            "groups": sorted(counts.items(), key=lambda x: (-x[1], x[0])), "total": len(items)}


def organize_apply(folder, rule, skip_links, names):
    plan = organize_plan(folder, rule, skip_links)
    folder = plan["folder"]
    chosen = set(names or [])
    journal = {"id": uuid.uuid4().hex[:8], "time": time.strftime("%Y-%m-%d %H:%M:%S"), "folder": folder, "rule": rule,
               "moves": [], "created": []}
    moved, failed = 0, []
    try:
        for it in plan["items"]:
            if it["name"] not in chosen:
                continue
            src = os.path.join(folder, it["name"])
            dest_dir = os.path.join(folder, it["group"])
            try:
                if not os.path.isdir(dest_dir):
                    parts = it["group"].split(os.sep)
                    acc = folder
                    for prt in parts:
                        acc = os.path.join(acc, prt)
                        if not os.path.isdir(acc):
                            os.mkdir(acc)
                            journal["created"].append(acc)
                dest = os.path.join(dest_dir, unique_name(dest_dir, it["name"], set()))
                os.rename(src, dest)  # same folder tree, so this is a fast rename; fails if the file is open/locked
                journal["moves"].append([src, dest])
                moved += 1
            except OSError as e:
                failed.append({"name": it["name"], "reason": "in use or locked" if getattr(e, "winerror", 0) in (32, 33, 5) else str(e)})
    finally:
        if journal["moves"] or journal["created"]:
            hist = load_undo()
            hist.append(journal)
            save_json(UNDO_FILE, hist[-20:])
    log_action("ORGANIZE", f"Moved {moved} file(s) in {folder} by {rule}; {len(failed)} skipped (in use) [undo id {journal['id']}]")
    return {"moved": moved, "failed": failed, "journal": journal["id"], "folder": folder}


def undo_summary():
    h = load_undo()
    if not h:
        return None
    j = h[-1]
    return {"id": j["id"], "time": j["time"], "folder": j["folder"], "rule": j["rule"], "count": len(j["moves"])}


def organize_undo():
    hist = load_undo()
    if not hist:
        raise ValueError("Nothing to undo")
    j = hist[-1]
    restored, failed = 0, []
    for src, dest in reversed(j["moves"]):
        if not (user_path_ok(src) and user_path_ok(dest)):
            failed.append({"name": os.path.basename(dest), "reason": "protected path"})
            continue
        try:
            if os.path.lexists(src):
                failed.append({"name": os.path.basename(src), "reason": "a file with that name is back in the folder"})
                continue
            os.rename(dest, src)
            restored += 1
        except OSError as e:
            failed.append({"name": os.path.basename(dest), "reason": str(e)})
    for d in reversed(j["created"]):
        try:
            os.rmdir(d)  # only removes folders this organize created, and only if empty
        except OSError:
            pass
    if failed:
        j["moves"] = [[s, d] for s, d in j["moves"] if os.path.lexists(d) and not os.path.lexists(s)]
        hist[-1] = j
    else:
        hist.pop()
    save_json(UNDO_FILE, hist)
    log_action("UNDO", f"Undid organize {j['id']} in {j['folder']}: restored {restored} file(s), {len(failed)} failed")
    return {"restored": restored, "failed": failed, "folder": j["folder"]}


# ---------------------------------------------------------------- HTTP
def state():
    r = SCAN["result"]
    s = load_settings()
    return {"version": VERSION, "home": HOME, "downloads": DOWNLOADS, "desktop": DESKTOP, "documents": DOCUMENTS, "drives": drives(), "settings": s,
            "scan": r["stats"] if r else None, "undo": undo_summary(), "cats": CATS["last"], "log": LOG_FILE,
            "jobs": {k: j.view(False) for k, j in CURRENT.items() if not j.done}, "types": TYPE_NAMES,
            "admin": is_admin(), "ai": ai_public(), "has_smart": bool(SMART["last"] or os.path.exists(SMART_FILE))}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _host_ok(self):
        return self.headers.get("Host", "") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")

    def _send(self, code, obj=None, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else (json.dumps(obj).encode("utf-8") if obj is not None else b"")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403)
        _last_ping[0] = time.time()
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        p = u.path
        if p in ("/", "/index.html"):
            return self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
        if p == "/favicon.ico":
            try:
                with open(os.path.join(APP_DIR, "cleanup.ico"), "rb") as f:
                    return self._send(200, f.read(), "image/x-icon")
            except OSError:
                return self._send(404)
        if p == "/api/ping":
            return self._send(204)
        if p == "/api/state":
            return self._send(200, state())
        if p == "/api/job":
            j = JOBS.get(q.get("id", ""))
            return self._send(200, j.view()) if j else self._send(404, {"error": "no such job"})
        if p == "/api/scan/dir":
            v = scan_dir_view(q.get("path"))
            return self._send(200, v) if v else self._send(404, {"error": "no scan"})
        if p == "/api/scan/largest":
            r = SCAN["result"]
            return self._send(200, {"items": r["largest"] if r else []})
        if p == "/api/scan/dups":
            r = SCAN["result"]
            return self._send(200, {"groups": r["dups"] if r else []})
        if p == "/api/scan/old":
            v = old_downloads(max(0, int(q.get("days", "90") or 90)))
            return self._send(200, v) if v else self._send(404, {"error": "no scan"})
        if p == "/api/activity":
            return self._send(200, {"items": read_log(), "path": LOG_FILE})
        try:
            r = ext_get(p, q)
        except Exception as e:
            log_action("ERROR", f"{p}: {e}")
            return self._send(500, {"error": str(e)})
        if r is not None:
            return self._send(200, r)
        self._send(404)

    def do_POST(self):
        # custom header = browsers must preflight, so other websites can't trigger these
        if not self._host_ok() or self.headers.get("X-PCClean") != "1":
            return self._send(403)
        _last_ping[0] = time.time()
        try:
            n = int(self.headers.get("Content-Length", "0") or 0)
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}") if n else {}
            return self._send(200, self.route(urlparse(self.path).path, body))
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            log_action("ERROR", f"{self.path}: {e}")
            return self._send(500, {"error": str(e)})

    def route(self, p, b):
        if p == "/api/scan/start":
            path = b.get("path") or HOME
            if not os.path.isdir(path):
                raise ValueError("That folder doesn't exist")
            s = load_settings()
            return start_job("scan", scan_job, path, int(s["dup_min_kb"]) * 1024).view(False)
        if p == "/api/job/cancel":
            j = JOBS.get(b.get("id", ""))
            if j:
                j.cancel.set()
            return {"ok": bool(j)}
        if p == "/api/cleanup/measure":
            return start_job("measure", measure_job).view(False)
        if p == "/api/cleanup/run":
            ids = [i for i in b.get("ids", []) if i in clean_ids()]
            if not ids:
                raise ValueError("Tick at least one category")
            dry = bool(b.get("dry", True))
            if not dry and b.get("confirm") != "yes":
                raise ValueError("Not confirmed")
            return start_job("clean", clean_job, ids, dry).view(False)
        if p == "/api/recycle/empty":
            if b.get("confirm") != "EMPTY":
                raise ValueError("Type EMPTY to confirm")
            info = recycle_bin_info()
            ok = empty_recycle_bin()
            log_action("EMPTY BIN", f"Emptied the Recycle Bin: {info['items']} item(s), {fmt(info['size'])} ({'ok' if ok else 'failed'})")
            return {"ok": ok, "freed": info["size"], "items": info["items"]}
        if p == "/api/recycle/info":
            return recycle_bin_info()
        if p == "/api/files/recycle":
            paths = [x for x in b.get("paths", []) if isinstance(x, str)][:2000]
            dry = bool(b.get("dry", False))
            if not dry and b.get("confirm") != "yes":
                raise ValueError("Not confirmed")
            return recycle_files(paths, dry)
        if p == "/api/organize/preview":
            plan = organize_plan(b.get("folder", ""), b.get("rule", "type"), bool(b.get("skip_links", True)))
            log_action("DRY RUN", f"Organize preview of {plan['folder']} by {plan['rule']}: {plan['total']} file(s) would move")
            return plan
        if p == "/api/organize/apply":
            if b.get("confirm") != "yes":
                raise ValueError("Not confirmed")
            return organize_apply(b.get("folder", ""), b.get("rule", "type"), bool(b.get("skip_links", True)), b.get("names", []))
        if p == "/api/organize/undo":
            return organize_undo()
        if p == "/api/settings":
            s = load_settings()
            for k, typ in (("old_days", int), ("dup_min_kb", int), ("skip_links", bool), ("rule", str)):
                if k in b:
                    s[k] = typ(b[k])
            s["old_days"] = max(0, min(3650, s["old_days"])); s["dup_min_kb"] = max(1, min(10 ** 7, s["dup_min_kb"]))
            save_json(SETTINGS_FILE, s)
            return s
        r = ext_post(p, b)
        if r is not None:
            return r
        raise ValueError("unknown endpoint")


def find_edge():
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")):
        if base:
            p = os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")
            if os.path.exists(p):
                return p
    if IS_WIN:  # Edge installed somewhere unusual: ask Windows (App Paths)
        import winreg
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe") as k:
                    p = (winreg.QueryValue(k, None) or "").strip('"')
                if p and os.path.exists(p):
                    return p
            except OSError:
                pass
    return None


def open_window():
    if NO_WINDOW:
        return
    edge = find_edge()
    if edge:
        profile = os.path.join(DATA_DIR, "window-profile")
        subprocess.Popen([edge, f"--app={APP_URL}", f"--user-data-dir={profile}", "--window-size=1180,800",
                          "--no-first-run", "--no-default-browser-check"])
    else:
        webbrowser.open(APP_URL)


def watchdog(server):
    while True:
        time.sleep(10)
        if time.time() - _last_ping[0] > IDLE_LIMIT and not any_job_running():
            server.shutdown()
            return


def main():
    server = None
    for _ in range(40 if ELEVATED_ARG else 1):  # an admin relaunch waits for the old instance to free the port
        try:
            server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
            break
        except OSError:
            if ELEVATED_ARG:
                time.sleep(0.5)
    if server is None:
        open_window()  # already running: just bring up a window
        return
    SERVER[0] = server
    os.makedirs(LOG_DIR, exist_ok=True)
    threading.Thread(target=watchdog, args=(server,), daemon=True).start()
    open_window()
    try:
        server.serve_forever()
    finally:
        server.server_close()


# ================================================================ v2/v3 modules: apps, protection, startup, monitor, health, dashboard, recommendations
import csv, shutil, struct, xml.etree.ElementTree as ET
if IS_WIN:
    import winreg
    K32 = ctypes.WinDLL("kernel32", use_last_error=True)
    SH32 = ctypes.WinDLL("shell32", use_last_error=True)
else:
    winreg = None

REG_BACKUP_DIR = os.path.join(DATA_DIR, "backups", "reg")
REG_INDEX = os.path.join(REG_BACKUP_DIR, "index.json")
AI_FILE = os.path.join(DATA_DIR, "ai-settings.json")
SMART_FILE = os.path.join(DATA_DIR, "smart-last.json")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
ELEVATED_ARG = "--elevated" in sys.argv
if "--no-window" in sys.argv:
    NO_WINDOW = True
_cache = {}


def cached(key, ttl, fn, force=False):
    hit = _cache.get(key)
    if hit and not force and time.time() - hit[0] < ttl:
        return hit[1]
    v = fn()
    _cache[key] = (time.time(), v)
    return v


def is_admin():
    if not IS_WIN:
        return os.environ.get("CLEANUP_FAKE_ADMIN") == "1"
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------- PowerShell helpers (read-only queries)
def psq(s):
    return "'" + str(s).replace("'", "''") + "'"


def run_ps(script, timeout=90):
    if not IS_WIN:
        return ""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; " + script],
                           capture_output=True, timeout=timeout, creationflags=NO_WINDOW_FLAG)
        return r.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def ps_json(script, timeout=90):
    out = run_ps("ConvertTo-Json -Depth 5 -Compress -InputObject @(" + script + ")", timeout).strip()
    if not out:
        return []
    try:
        d = json.loads(out[out.find("["):] if "[" in out else out)
    except ValueError:
        return []
    return d if isinstance(d, list) else [d]


# ---------------------------------------------------------------- registry helpers
HIVE_NAMES = ("HKCU", "HKLM")


def _hive(h):
    return {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[h]


def reg_values(hive, path, view=0):
    if not IS_WIN:
        return None
    try:
        k = winreg.OpenKey(_hive(hive), path, 0, winreg.KEY_READ | view)
    except OSError:
        return None
    out = {}
    with k:
        i = 0
        while True:
            try:
                n, v, _ = winreg.EnumValue(k, i)
            except OSError:
                break
            out[n] = v
            i += 1
    return out


def reg_subkeys(hive, path, view=0):
    if not IS_WIN:
        return []
    try:
        k = winreg.OpenKey(_hive(hive), path, 0, winreg.KEY_READ | view)
    except OSError:
        return []
    out = []
    with k:
        i = 0
        while True:
            try:
                out.append(winreg.EnumKey(k, i))
            except OSError:
                break
            i += 1
    return out


def reg_exists(hive, path, view=0):
    if not IS_WIN:
        return False
    try:
        winreg.CloseKey(winreg.OpenKey(_hive(hive), path, 0, winreg.KEY_READ | view))
        return True
    except OSError:
        return False


V64 = 0x100
V32 = 0x200


# ---------------------------------------------------------------- name matching (uninstaller leftovers)
STOP = set("inc corp corporation llc ltd limited co company gmbh ag sa the software technologies technology systems x64 x86 "
           "64 32 bit version edition for update setup installer app apps and of by desktop client".split())
GENERIC = set("microsoft windows common files packages temp tmp programs program files google intel nvidia amd "
              "realtek package cache installer crashdumps cache caches logs log data users public default identities "
              "comms connecteddevicesplatform d3dscache diagnostics history help ssh python pip npm "
              "windowsapps reference assemblies msbuild uninstall information dotnet regid".split())


def norm_name(s):
    s = re.sub(r"\([^)]*\)", " ", str(s or "").lower())
    s = re.sub(r"\b\d+(\.\d+)+\b", " ", s)
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return s.strip()


def toks(s):
    return [w for w in norm_name(s).split() if w not in STOP and len(w) > 1]


def compact(s):
    return "".join(toks(s))


def match_score(folder_name, product, publisher, others=()):
    """Confidence 0-100 that a folder/key named folder_name belongs to product. Conservative."""
    cf, cp, cu = compact(folder_name), compact(product), compact(publisher)
    if not cf or norm_name(folder_name) in GENERIC or cf in GENERIC:
        return 0
    if cf in others and cf != cp:
        return 0  # belongs to another installed program
    if cp and cf == cp:
        return 95
    if cp and len(cf) >= 5 and len(cp) >= 5 and (cp.startswith(cf) or cf.startswith(cp)):
        return 75
    tp = toks(product)
    if tp and len(tp[0]) >= 4 and cf == tp[0]:
        return 60
    if cu and len(cu) >= 4 and cf == cu:
        return 45
    return 0


# ---------------------------------------------------------------- installed programs
UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"


def _uninstall_sources():
    return [("HKLM", V64, "64-bit"), ("HKLM", V32, "32-bit"), ("HKCU", 0, "this user")]


def list_programs():
    out, seen = [], set()
    for hive, view, scope in _uninstall_sources():
        for sk in reg_subkeys(hive, UNINSTALL, view):
            v = reg_values(hive, UNINSTALL + "\\" + sk, view) or {}
            name = str(v.get("DisplayName") or "").strip()
            if not name or v.get("SystemComponent") == 1 or v.get("ParentKeyName") or \
                    str(v.get("ReleaseType") or "") in ("Update", "Hotfix", "Security Update"):
                continue
            dk = (name.lower(), str(v.get("DisplayVersion") or ""))
            if dk in seen:
                continue
            seen.add(dk)
            d = str(v.get("InstallDate") or "")
            es = v.get("EstimatedSize")
            out.append({"id": f"{hive}|{view}|{sk}", "name": name, "publisher": str(v.get("Publisher") or ""),
                        "version": str(v.get("DisplayVersion") or ""), "size": es * 1024 if isinstance(es, int) else 0,
                        "date": f"{d[:4]}-{d[4:6]}-{d[6:8]}" if re.fullmatch(r"\d{8}", d) else "",
                        "location": str(v.get("InstallLocation") or "").strip().strip('"'),
                        "uninstall": str(v.get("UninstallString") or ""), "quiet": str(v.get("QuietUninstallString") or ""),
                        "hive": hive, "scope": scope, "key": f"{hive}\\{UNINSTALL}\\{sk}", "msi": v.get("WindowsInstaller") == 1})
    out.sort(key=lambda x: x["name"].lower())
    return out


def store_apps():
    rows = ps_json("Get-AppxPackage -EA SilentlyContinue | Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' -and "
                   "-not $_.IsResourcePackage } | ForEach-Object { [pscustomobject]@{n=$_.Name; p=($_.Publisher -replace '^CN=([^,]+).*','$1'); "
                   "v=[string]$_.Version; l=$_.InstallLocation; s=[string]$_.SignatureKind} }", 120)
    return [{"name": r.get("n", ""), "publisher": r.get("p", ""), "version": r.get("v", ""), "location": r.get("l") or "",
             "kind": r.get("s", "")} for r in rows if isinstance(r, dict)]


def programs_payload(force=False):
    progs = cached("programs", 60, list_programs, force)
    return {"programs": progs, "admin": is_admin(), "count": len(progs)}


def find_program(pid):
    for p in list_programs():
        if p["id"] == pid:
            return p
    return None


def split_cmd(cmd):
    cmd = os.path.expandvars(cmd.strip())
    if cmd.startswith('"'):
        exe, _, rest = cmd[1:].partition('"')
        return exe, rest.strip()
    m = re.match(r"(?i)^(.+?\.(exe|cmd|bat|com))(\s+|$)(.*)$", cmd)
    if m:
        return m.group(1), m.group(4).strip()
    exe, _, rest = cmd.partition(" ")
    return exe, rest


def uninstall_command(p, quiet=False):
    cmd = (p["quiet"] if quiet and p["quiet"] else p["uninstall"]) or ""
    m = re.search(r"(?i)msiexec(?:\.exe)?\"?\s+/[ix]\s*(\{[0-9a-f\-]{36}\})", cmd)
    if m:
        return "msiexec.exe", f"/x {m.group(1)}" + (" /qb" if quiet else "")
    if not cmd:
        raise ValueError("This program has no uninstaller registered")
    return split_cmd(cmd)


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint32), ("fMask", ctypes.c_ulong), ("hwnd", ctypes.c_void_p), ("lpVerb", ctypes.c_wchar_p),
                ("lpFile", ctypes.c_wchar_p), ("lpParameters", ctypes.c_wchar_p), ("lpDirectory", ctypes.c_wchar_p), ("nShow", ctypes.c_int),
                ("hInstApp", ctypes.c_void_p), ("lpIDList", ctypes.c_void_p), ("lpClass", ctypes.c_wchar_p), ("hkeyClass", ctypes.c_void_p),
                ("dwHotKey", ctypes.c_uint32), ("hIcon", ctypes.c_void_p), ("hProcess", ctypes.c_void_p)]


def shell_run(file, params, verb="open", wait_job=None, max_wait=3600):
    """ShellExecuteEx so the program's own UAC prompt can appear (never elevates silently). Returns exit code or None."""
    if not IS_WIN:
        r = subprocess.run([file] + (params.split() if params else []), capture_output=True)
        return r.returncode
    ctypes.windll.ole32.CoInitialize(None)
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40 | 0x400  # SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI
    info.lpVerb, info.lpFile, info.lpParameters, info.nShow = verb, file, params or None, 1
    SH32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    if not SH32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.get_last_error()
        raise OSError("Cancelled at the Windows prompt" if err == 1223 else f"Couldn't start it (error {err})")
    if not info.hProcess:
        return None
    K32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    K32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    K32.CloseHandle.argtypes = [ctypes.c_void_p]
    t0 = time.time()
    try:
        while K32.WaitForSingleObject(info.hProcess, 500) == 0x102:
            if (wait_job and wait_job.cancel.is_set()) or time.time() - t0 > max_wait:
                return None
        code = ctypes.c_uint32()
        K32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        return code.value
    finally:
        K32.CloseHandle(info.hProcess)


# ---------------------------------------------------------------- leftovers
LEFT = {}


def leftover_roots():
    pf = [os.environ.get(k) for k in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)")]
    roots = [(r, True) for r in dict.fromkeys(x for x in pf if x)]
    if os.environ.get("ProgramData"):
        roots.append((os.environ["ProgramData"], True))
    ad = os.environ.get("APPDATA") or os.path.join(HOME, "AppData", "Roaming")
    roots += [(ad, False), (LOCALAPPDATA, False), (os.path.join(LOCALAPPDATA, "Programs"), False), (os.path.join(HOME, "AppData", "LocalLow"), False)]
    roots += [(p, False) for p in os.environ.get("CLEANUP_LEFTOVER_ROOTS", "").split(os.pathsep) if p]
    seen, out = set(), []
    for r, a in roots:
        if os.path.isdir(r) and norm(r) not in seen:
            seen.add(norm(r))
            out.append((r, a))
    return out


def folder_size(path, cap=30000):
    tot = n = 0
    for d, subs, files in os.walk(path):
        subs[:] = [s for s in subs if not os.path.islink(os.path.join(d, s))]
        for f in files:
            try:
                st = os.stat(os.path.join(d, f), follow_symlinks=False)
                if not is_cloud(st):
                    tot += st.st_size
            except OSError:
                pass
            n += 1
            if n > cap:
                return tot
    return tot


def other_names(prog_id, progs):
    return {compact(p["name"]) for p in progs if p.get("id") != prog_id}


def same_publisher_count(pub, progs):
    cu = compact(pub)
    return sum(1 for p in progs if cu and compact(p["publisher"]) == cu)


def start_menu_roots():
    return [os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs"),
            os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Windows", "Start Menu", "Programs"), DESKTOP,
            os.path.join(os.environ.get("PUBLIC", ""), "Desktop")]


def find_leftovers(prog, progs=None, still_installed=False):
    """Read-only. Returns candidate leftovers with a confidence score."""
    progs = progs if progs is not None else list_programs()
    others = other_names(prog.get("id"), progs)
    name, pub = prog["name"], prog.get("publisher", "")
    solo_pub = same_publisher_count(pub, [p for p in progs if p.get("id") != prog.get("id")]) == 0
    admin = is_admin()
    items, seen = [], set()
    loc = norm(prog["location"]) if prog.get("location") else None
    root_norms = [norm(r) for r, _ in leftover_roots()]

    def add(kind, path, conf, admin_needed, why, size=None, view=""):
        k = (kind, os.path.normcase(path))
        if k in seen:
            for it in items:
                if (it["kind"], os.path.normcase(it["path"])) == k and conf > it["confidence"]:
                    it["confidence"], it["why"] = conf, why
            return
        seen.add(k)
        items.append({"kind": kind, "path": path, "confidence": conf, "needs_admin": bool(admin_needed and not admin), "why": why, "view": view,
                      "size": size if size is not None else (folder_size(path) if kind == "folder" else 0)})

    for root, admin_root in leftover_roots():
        try:
            entries = [e for e in os.scandir(root) if e.is_dir(follow_symlinks=False) and not e.is_symlink()]
        except OSError:
            continue
        for e in entries:
            if loc and norm(e.path) == loc:
                add("folder", e.path, 100, admin_root, "install folder from the registry")
                continue
            sc = match_score(e.name, name, pub, others)
            if sc == 45:  # publisher folder: look inside for the product; flag the whole folder only if no other program uses it
                hit = False
                try:
                    for s in os.scandir(e.path):
                        if s.is_dir(follow_symlinks=False) and loc and norm(s.path) == loc:
                            add("folder", s.path, 100, admin_root, "install folder from the registry")
                            hit = True
                        elif s.is_dir(follow_symlinks=False) and match_score(s.name, name, "", others) >= 60:
                            add("folder", s.path, 90, admin_root, f"product folder inside publisher folder {e.name}")
                            hit = True
                except OSError:
                    pass
                if not hit and solo_pub and not still_installed:
                    add("folder", e.path, 45, admin_root, "publisher folder; no other programs from this publisher are installed")
            elif sc:
                add("folder", e.path, sc, admin_root, "folder name matches the program")
    if loc and os.path.isdir(prog["location"]) and loc not in root_norms and not any(norm(i["path"]) == loc for i in items):
        add("folder", prog["location"], 100, not under(loc, norm(HOME)), "install folder from the registry")
    # registry: Software\<Product> and Software\<Publisher>\<Product>
    for hive, view in (("HKCU", 0), ("HKLM", V64), ("HKLM", V32)):
        vs = "" if hive == "HKCU" else ("/reg:64" if view == V64 else "/reg:32")
        for sk in reg_subkeys(hive, "Software", view):
            if sk.lower() in ("microsoft", "classes", "policies", "wow6432node", "clients", "registeredapplications", "windows"):
                continue
            sc = match_score(sk, name, pub, others)
            if sc >= 60:
                add("regkey", f"{hive}\\Software\\{sk}", min(sc, 85), hive == "HKLM", "registry key matches the program", 0, vs)
            elif sc == 45:
                for c in reg_subkeys(hive, "Software\\" + sk, view):
                    if match_score(c, name, "", others) >= 60:
                        add("regkey", f"{hive}\\Software\\{sk}\\{c}", 85, hive == "HKLM", f"product key under publisher key {sk}", 0, vs)
    if not still_installed and prog.get("key"):
        hive, _, path = prog["key"].partition("\\")
        view = int(prog["id"].split("|")[1]) if prog.get("id") else 0
        if reg_exists(hive, path, view):
            add("regkey", prog["key"], 90, hive == "HKLM", "uninstall entry left behind", 0,
                "" if hive == "HKCU" else ("/reg:64" if view == V64 else "/reg:32"))
    # Start Menu and Desktop shortcuts
    for i, root in enumerate(start_menu_roots()):
        if not root or not os.path.isdir(root):
            continue
        for d, subs, files in os.walk(root):
            for f in subs:
                if match_score(f, name, "", others) >= 75:
                    add("shortcut", os.path.join(d, f), 80, i in (1, 3), "Start Menu folder", 0)
            for f in files:
                if f.lower().endswith((".lnk", ".url")) and match_score(os.path.splitext(f)[0], name, "", others) >= 75:
                    add("shortcut", os.path.join(d, f), 80, i in (1, 3), "Start Menu / Desktop shortcut", 0)
    # scheduled tasks (review-only)
    folders = [i["path"].lower() for i in items if i["kind"] == "folder"]
    for t in scheduled_tasks():
        if match_score(t["name"], name, "", others) >= 60 or any(f in t["action"].lower() for f in folders):
            add("task", t["path"] + t["name"], 70, True, "scheduled task (review in Task Scheduler)", 0)
    items.sort(key=lambda x: (-x["confidence"], x["kind"]))
    return items


def leftovers_result(prog, items, note=""):
    tok = uuid.uuid4().hex[:12]
    LEFT[tok] = {"prog": prog, "items": items, "time": time.time()}
    for k in list(LEFT):
        if time.time() - LEFT[k]["time"] > 3600:
            LEFT.pop(k, None)
    return {"token": tok, "program": prog["name"], "items": items, "note": note,
            "size": sum(i["size"] for i in items), "admin": is_admin()}


def leftover_folder_ok(path, install_loc=""):
    rp = norm(path)
    roots = [norm(r) for r, _ in leftover_roots()]
    if rp in roots or os.path.dirname(rp) == rp:
        return False
    if install_loc and rp == norm(install_loc):
        # the program's own registered install folder outside the usual roots (e.g. C:\Tools\App):
        # allowed only if it is at least two levels deep and is not, or does not contain, a system/user root
        keep = [norm(x) for x in (HOME, os.environ.get("SystemRoot"), os.environ.get("SystemDrive", "C:") + "\\Users", AGENT_DIR) if x] + roots
        sysroot = os.environ.get("SystemRoot")
        if (len([x for x in rp.replace("/", "\\").split("\\") if x]) >= 3 and not any(k == rp or under(k, rp) for k in keep)
                and not (sysroot and under(rp, norm(sysroot))) and (not under(rp, norm(AGENT_DIR)) or under(rp, SANDBOX_N))
                and (not under(rp, norm(HOME)) or under(rp, SANDBOX_N))
                and norm_name(os.path.basename(rp)) not in GENERIC):
            return True
    sysroot = os.environ.get("SystemRoot")
    if sysroot and under(rp, norm(sysroot)):
        return False
    if under(rp, norm(AGENT_DIR)) and not under(rp, SANDBOX_N):
        return False
    starts = [norm(r) for r in start_menu_roots() if r]
    if rp in starts:
        return False
    return any(under(rp, r) for r in roots + starts) and norm_name(os.path.basename(rp)) not in GENERIC


def regkey_ok(key):
    parts = key.split("\\")
    if len(parts) < 3 or parts[0] not in HIVE_NAMES or parts[1].lower() != "software" or not parts[2]:
        return False
    sub = "\\".join(parts[2:]).lower()
    if sub.startswith("microsoft\\windows\\currentversion\\uninstall\\") and len(parts) == 7:
        return True  # a single program's own uninstall entry
    return parts[2].lower() not in ("microsoft", "classes", "policies", "wow6432node", "windows", "clients", "registeredapplications")


def reg_cli(args, timeout=60):
    r = subprocess.run(["reg"] + args, capture_output=True, timeout=timeout, creationflags=NO_WINDOW_FLAG)
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace").strip()


def backup_and_delete_key(key, view=""):
    if not regkey_ok(key):
        raise ValueError(f"Refused registry key: {key}")
    os.makedirs(REG_BACKUP_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", key.split("\\")[-1])[:60]
    f = os.path.join(REG_BACKUP_DIR, f"{stamp}-{safe}.reg")
    rc, out = reg_cli(["export", key, f, "/y"] + ([view] if view else []))
    if rc != 0 or not os.path.exists(f):
        raise OSError(f"Backup failed, key not deleted: {out}")
    rc, out = reg_cli(["delete", key, "/f"] + ([view] if view else []))
    if rc != 0:
        raise OSError(f"Delete failed (backup kept at {f}): {out}")
    idx = load_json(REG_INDEX, [])
    idx.append({"file": os.path.basename(f), "key": key, "view": view, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "restored": ""})
    save_json(REG_INDEX, idx[-200:])
    log_action("REGISTRY", f"Backed up to {f} then deleted {key}")
    return f


def reg_backups():
    return list(reversed(load_json(REG_INDEX, [])))


def reg_restore(fname):
    idx = load_json(REG_INDEX, [])
    ent = next((e for e in idx if e["file"] == fname), None)
    f = os.path.join(REG_BACKUP_DIR, os.path.basename(fname))
    if not ent or not os.path.isfile(f):
        raise ValueError("No such backup")
    if ent["key"].startswith("HKLM") and not is_admin():
        raise ValueError("Restoring an HKLM key needs admin. Use Relaunch as admin first.")
    rc, out = reg_cli(["import", f] + ([ent["view"]] if ent.get("view") else []))
    if rc != 0:
        raise OSError(f"Restore failed: {out}")
    ent["restored"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_json(REG_INDEX, idx)
    log_action("RESTORE", f"Restored {ent['key']} from {f}")
    return {"ok": True, "key": ent["key"]}


def remove_leftovers(token, idxs):
    L = LEFT.get(token)
    if not L:
        raise ValueError("That leftover list expired. Scan again.")
    done, failed = [], []
    for i in idxs:
        if not isinstance(i, int) or not 0 <= i < len(L["items"]):
            continue
        it = L["items"][i]
        if it.get("removed"):
            continue
        try:
            if it["needs_admin"] and not is_admin():
                raise ValueError("needs admin")
            if it["kind"] in ("folder", "shortcut"):
                if not leftover_folder_ok(it["path"], L["prog"].get("location", "")) or not os.path.lexists(it["path"]):
                    raise ValueError("protected or missing")
                if not send_to_recycle_bin(it["path"]):
                    raise OSError("in use or cancelled")
                log_action("RECYCLE", f"Leftover of {L['prog']['name']} to Recycle Bin: {it['path']} ({fmt(it['size'])})")
            elif it["kind"] == "regkey":
                it["backup"] = backup_and_delete_key(it["path"], it.get("view", ""))
            else:
                raise ValueError("review-only item")
            it["removed"] = True
            done.append(i)
        except Exception as e:
            failed.append({"i": i, "path": it["path"], "reason": str(e)})
    return {"removed": done, "failed": failed, "items": L["items"]}


def uninstall_job(job, prog, quiet):
    exe, params = uninstall_command(prog, quiet)
    job.progress.update(phase="uninstall", current=prog["name"])
    log_action("UNINSTALL", f"Started the uninstaller for {prog['name']} {prog['version']}: {exe} {params}")
    progs_before = list_programs()
    code = shell_run(exe, params, wait_job=job)
    job.progress.update(phase="leftovers", current="Looking for leftovers")
    time.sleep(1.5)
    gone = find_program(prog["id"]) is None
    log_action("UNINSTALL", f"{prog['name']}: uninstaller exit code {code}; entry {'removed' if gone else 'still present'}")
    items = find_leftovers(prog, progs_before, still_installed=not gone)
    _cache.pop("programs", None)
    r = leftovers_result(prog, items, "" if gone else "The program still looks installed (the uninstaller may have been cancelled).")
    r.update(exit_code=code, removed=gone)
    return r


def orphan_scan(job=None):
    """AppData/ProgramData folders that match no installed program. Low confidence, review-only."""
    progs = list_programs()
    names = {compact(p["name"]) for p in progs} | {compact(p["publisher"]) for p in progs}
    for p in progs:
        t = toks(p["name"])
        if t:
            names.add(t[0])
    names.discard("")
    roots = [os.environ.get("APPDATA") or os.path.join(HOME, "AppData", "Roaming"), LOCALAPPDATA,
             os.path.join(HOME, "AppData", "LocalLow"), os.environ.get("ProgramData") or ""]
    out = []
    for r in roots:
        if not r or not os.path.isdir(r):
            continue
        for e in os.scandir(r):
            if not e.is_dir(follow_symlinks=False) or e.name.startswith((".", "{")):
                continue
            c = compact(e.name)
            if not c or norm_name(e.name) in GENERIC or c in GENERIC or \
                    any(c == n or (len(c) >= 4 and len(n) >= 4 and (n.startswith(c) or c.startswith(n))) for n in names):
                continue
            if job:
                job.progress["current"] = e.path
            try:
                mt = e.stat().st_mtime
            except OSError:
                mt = 0
            out.append({"path": e.path, "size": folder_size(e.path, 8000), "mtime": mt, "confidence": 20})
    out.sort(key=lambda x: -x["size"])
    return {"items": out[:200], "count": len(out)}


# ---------------------------------------------------------------- scheduled tasks and services (one PowerShell call each, cached)
def scheduled_tasks(force=False):
    def q():
        rows = ps_json("Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | "
                       "ForEach-Object { [pscustomobject]@{n=$_.TaskName; p=$_.TaskPath; s=[string]$_.State; au=[string]$_.Author; "
                       "u=[string]$_.Principal.UserId; rl=[string]$_.Principal.RunLevel; "
                       "a=(@($_.Actions | Where-Object { $_.Execute } | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' | '); "
                       "t=(@($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ',')} }", 120)
        return [{"name": r.get("n", ""), "path": r.get("p", "\\"), "state": r.get("s", ""), "author": r.get("au", ""),
                 "user": r.get("u") or "", "runlevel": r.get("rl") or "",
                 "action": r.get("a") or "", "triggers": r.get("t") or ""} for r in rows if isinstance(r, dict)]
    return cached("tasks", 120, q, force)


def exe_from_cmd(cmd):
    cmd = os.path.expandvars(str(cmd or "").strip())
    if not cmd:
        return ""
    exe, rest = split_cmd(cmd)
    if os.path.basename(exe).lower() in ("rundll32.exe", "rundll32"):
        m = re.match(r'\s*"?([^",]+\.dll)', rest, re.I)
        if m:
            exe = m.group(1)
    return exe


def auto_services(force=False):
    def q():
        rows = ps_json("Get-CimInstance Win32_Service -Filter \"StartMode='Auto'\" -EA SilentlyContinue | ForEach-Object { "
                       "[pscustomobject]@{n=$_.Name; d=$_.DisplayName; p=$_.PathName; s=$_.State} }", 90)
        sysroot = (os.environ.get("SystemRoot") or r"C:\Windows").lower()
        out = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            exe = exe_from_cmd(r.get("p") or "")
            if not exe or exe.lower().startswith(sysroot):
                continue
            out.append({"name": r.get("n", ""), "display": r.get("d", ""), "cmd": r.get("p") or "", "exe": exe, "state": r.get("s", "")})
        return out
    return cached("services", 120, q, force)


SIG = {}


def signatures(paths):
    want = [p for p in dict.fromkeys(paths) if p and p not in SIG]
    exist = [p for p in want if os.path.isfile(p)]
    for p in want:
        if p not in exist:
            SIG[p] = {"status": "Missing", "signer": ""}
    for i in range(0, len(exist), 40):
        chunk = exist[i:i + 40]
        rows = ps_json("foreach($x in @(" + ",".join(psq(p) for p in chunk) + ")){ $s=Get-AuthenticodeSignature -LiteralPath $x -EA SilentlyContinue; "
                       "[pscustomobject]@{p=$x; s=[string]$s.Status; c=$(if($s.SignerCertificate){$s.SignerCertificate.GetNameInfo('SimpleName',$false)}else{''})} }", 120)
        for r in rows:
            if isinstance(r, dict) and r.get("p"):
                SIG[r["p"]] = {"status": r.get("s") or "Unknown", "signer": r.get("c") or ""}
        for p in chunk:
            SIG.setdefault(p, {"status": "Unknown", "signer": ""})
    return {p: SIG.get(p, {"status": "Unknown", "signer": ""}) for p in paths}


# ---------------------------------------------------------------- startup manager
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUNONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
SAPPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
FAKE_REG = {}


def approved_enabled(v):
    return not (isinstance(v, (bytes, bytearray)) and len(v) >= 1 and v[0] & 1)


def user_startup_dir():
    return os.path.join(os.environ.get("APPDATA") or os.path.join(HOME, "AppData", "Roaming"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")


def common_startup_dir():
    return os.path.join(os.environ.get("ProgramData") or r"C:\ProgramData", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")


def resolve_lnks(paths):
    if not paths:
        return {}
    rows = ps_json("$w=New-Object -ComObject WScript.Shell; foreach($x in @(" + ",".join(psq(p) for p in paths) + ")){ $s=$w.CreateShortcut($x); "
                   "[pscustomobject]@{p=$x; t=$s.TargetPath; a=$s.Arguments} }", 30)
    return {r["p"]: (r.get("t") or "", r.get("a") or "") for r in rows if isinstance(r, dict) and r.get("p")}


def impact_of(exe):
    try:
        s = os.path.getsize(exe)
    except OSError:
        return "unknown", 0
    return ("low" if s < 5 * 2 ** 20 else "medium" if s < 50 * 2 ** 20 else "high"), s


WRAPPERS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "conhost.exe", "powershell", "pwsh", "cmd", "mshta.exe"}
TARGET_RE = re.compile(r"""([A-Za-z]:[\\/][^"'|<>\r\n]*?\.(?:exe|ps1|cmd|bat|vbs|js|py|pyw|lnk|jar))(?=["'\s]|$)""", re.I)


def resolve_target(cmd, exe):
    """The file a startup entry really runs. For powershell/cmd/wscript wrappers that's the script or program they launch."""
    exe = exe or ""
    if os.path.basename(exe).lower() in WRAPPERS:
        _, rest = split_cmd(os.path.expandvars(str(cmd or "").split(" | ")[0]))
        m = TARGET_RE.search(rest or "")
        if m:
            return m.group(1)
        w = shutil.which(exe)
        return w or exe
    if exe and not os.path.isabs(exe):
        return shutil.which(exe) or exe
    return exe


def target_problem(target):
    """Why a startup entry is broken ('' if it isn't)."""
    if not target or not os.path.isabs(target) or target.lower().endswith(".url"):
        return ""
    drive = os.path.splitdrive(target)[0]
    if IS_WIN and drive and not os.path.exists(drive + "\\"):
        return f"it points to drive {drive}, which isn't connected"
    if not os.path.exists(target):
        return "the file it starts no longer exists"
    return ""


def task_can_toggle(t, admin):
    """Only your own tasks in the Task Scheduler root folder (never \\Microsoft\\ or other users' tasks)."""
    me = (os.environ.get("USERNAME") or "").lower()
    u = (t.get("user") or "").lower().split("\\")[-1]
    return t.get("path") == "\\" and bool(me) and u == me and (t.get("runlevel") != "Highest" or admin)


def suspicious_path(p):
    pl = (p or "").lower()
    return any(x in pl for x in ("\\appdata\\", "\\temp\\", "\\users\\public\\")) and "\\microsoft\\windowsapps\\" not in pl


def startup_items(force=False):
    admin = is_admin()
    items = []
    for hive, view, sa in (("HKCU", 0, "Run"), ("HKLM", V64, "Run"), ("HKLM", V32, "Run32")):
        appr = reg_values(hive, SAPPROVED + "\\" + sa, V64 if hive == "HKLM" else 0) or {}
        for name, cmd in (reg_values(hive, RUN, view) or {}).items():
            if not name:
                continue
            items.append({"id": f"run|{hive}|{sa}|{name}", "name": name, "kind": "Registry Run", "where": f"{hive}\\{RUN}" + (" (32-bit)" if view == V32 else ""),
                          "cmd": str(cmd), "exe": exe_from_cmd(cmd), "enabled": approved_enabled(appr.get(name)),
                          "can_toggle": hive == "HKCU" or admin, "needs_admin": hive == "HKLM" and not admin, "scope": "user" if hive == "HKCU" else "all users"})
        for name, cmd in (reg_values(hive, RUNONCE, view) or {}).items():
            if name:
                items.append({"id": f"once|{hive}|{view}|{name}", "name": name, "kind": "RunOnce (next login only)", "where": f"{hive}\\{RUNONCE}", "cmd": str(cmd),
                              "exe": exe_from_cmd(cmd), "enabled": True, "can_toggle": False, "needs_admin": False, "scope": "once"})
    folder_items = []
    for hive, d in (("HKCU", user_startup_dir()), ("HKLM", common_startup_dir())):
        appr = reg_values(hive, SAPPROVED + "\\StartupFolder", V64 if hive == "HKLM" else 0) or {}
        try:
            names = sorted(os.listdir(d))
        except OSError:
            names = []
        for f in names:
            if f.lower() == "desktop.ini":
                continue
            folder_items.append((hive, d, f, approved_enabled(appr.get(f))))
    lnk = resolve_lnks([os.path.join(d, f) for _, d, f, _ in folder_items if f.lower().endswith(".lnk")]) if IS_WIN else {}
    for hive, d, f, en in folder_items:
        p = os.path.join(d, f)
        exe, args = lnk.get(p, (p, ""))
        items.append({"id": f"folder|{hive}|StartupFolder|{f}", "name": os.path.splitext(f)[0], "kind": "Startup folder", "where": d,
                      "cmd": (exe + " " + args).strip(), "exe": exe or p, "enabled": en, "path": p,
                      "can_toggle": hive == "HKCU" or admin, "needs_admin": hive == "HKLM" and not admin, "scope": "user" if hive == "HKCU" else "all users"})
    for t in scheduled_tasks(force):
        if "Logon" in t["triggers"] or "Boot" in t["triggers"]:
            ct = task_can_toggle(t, admin)
            items.append({"id": f"task|{t['path']}{t['name']}", "name": t["name"], "kind": "Scheduled task (" + ("boot" if "Boot" in t["triggers"] else "logon") + ")",
                          "where": "Task Scheduler " + t["path"], "cmd": t["action"], "exe": exe_from_cmd(t["action"].split(" | ")[0]),
                          "enabled": t["state"] != "Disabled", "can_toggle": ct, "scope": "task",
                          "needs_admin": t.get("path") == "\\" and t.get("runlevel") == "Highest" and not admin})
    for s in auto_services(force):
        items.append({"id": f"svc|{s['name']}", "name": s["display"] or s["name"], "kind": "Auto-start service", "where": f"Service {s['name']} ({s['state']})",
                      "cmd": s["cmd"], "exe": s["exe"], "enabled": True, "can_toggle": False, "needs_admin": False, "scope": "service"})
    for i in items:
        i["target"] = resolve_target(i["cmd"], i["exe"])
    sigs = signatures([i["target"] or i["exe"] for i in items if i["target"] or i["exe"]])
    out = []
    for i in items:
        tgt = i["target"] or i["exe"]
        sg = sigs.get(tgt, {"status": "Unknown", "signer": ""})
        if i["kind"] == "Auto-start service" and "microsoft" in sg["signer"].lower():
            continue  # Microsoft's own services aren't interesting here
        i["signature"], i["publisher"] = sg["status"], sg["signer"]
        i["impact"], i["size"] = impact_of(tgt)
        i["broken_reason"] = target_problem(tgt)
        i["broken"] = bool(i["broken_reason"])
        i["suspicious"] = bool(suspicious_path(tgt) and sg["status"] not in ("Valid", "Missing")) or sg["status"] in ("HashMismatch", "NotTrusted")
        out.append(i)
    return out


def startup_payload(force=False):
    items = cached("startup", 60, lambda: startup_items(force), force)
    return {"items": items, "admin": is_admin(), "enabled": sum(1 for i in items if i["enabled"]),
            "suspicious": sum(1 for i in items if i["suspicious"]), "broken": sum(1 for i in items if i.get("broken") and i["enabled"]),
            "total": len(items)}


def filetime_now():
    return int((time.time() + 11644473600) * 10 ** 7)


def task_set(item_id, enable):
    items = cached("startup", 300, startup_items) if IS_WIN else (_cache.get("startup") or (0, []))[1]
    it = next((i for i in items if i["id"] == item_id), None)
    if not it:
        raise ValueError("That startup item no longer exists")
    if not it.get("can_toggle"):
        raise ValueError("Only your own tasks in the Task Scheduler root can be switched here" + (" (this one needs admin)" if it.get("needs_admin") else ""))
    tn = item_id.split("|", 1)[1]
    if IS_WIN:
        r = subprocess.run(["schtasks", "/Change", "/TN", tn, "/ENABLE" if enable else "/DISABLE"], capture_output=True, text=True,
                           timeout=30, creationflags=NO_WINDOW_FLAG)
        if r.returncode != 0:
            raise ValueError("Windows didn't allow changing this task: " + (r.stderr or r.stdout or "").strip()[:160])
    else:
        FAKE_REG["task|" + tn] = enable
    it["enabled"] = enable
    _cache.pop("tasks", None)
    log_action("STARTUP", f"{'Enabled' if enable else 'Disabled'} scheduled task '{tn}' (reversible: schtasks /Change /{'DISABLE' if enable else 'ENABLE'})")
    return {"ok": True, "id": item_id, "enabled": enable}


def startup_set(item_id, enable):
    if item_id.startswith("task|"):
        return task_set(item_id, enable)
    kind, hive, sub, name = (item_id.split("|", 3) + ["", "", ""])[:4]
    if kind not in ("run", "folder") or hive not in HIVE_NAMES or sub not in ("Run", "Run32", "StartupFolder") or not name:
        raise ValueError("This item can't be switched here")
    if hive == "HKLM" and not is_admin():
        raise ValueError("This item is for all users and needs admin. Use Relaunch as admin.")
    items = cached("startup", 300, startup_items) if IS_WIN else (_cache.get("startup") or (0, []))[1]
    if not any(i["id"] == item_id for i in items):
        raise ValueError("That startup item no longer exists")
    val = (b"\x02" + b"\x00" * 11) if enable else (b"\x03\x00\x00\x00" + struct.pack("<Q", filetime_now()))
    if IS_WIN:
        with winreg.CreateKeyEx(_hive(hive), SAPPROVED + "\\" + sub, 0, winreg.KEY_SET_VALUE | (V64 if hive == "HKLM" else 0)) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, val)
    else:
        FAKE_REG[f"{hive}\\{SAPPROVED}\\{sub}\\{name}"] = val
    for i in items:
        if i["id"] == item_id:
            i["enabled"] = enable
    log_action("STARTUP", f"{'Enabled' if enable else 'Disabled'} startup item '{name}' ({hive} {sub}) via StartupApproved (reversible)")
    return {"ok": True, "id": item_id, "enabled": enable}


# ---------------------------------------------------------------- protection (read-only)
RISKY_PERMS = {"webRequest", "webRequestBlocking", "proxy", "nativeMessaging", "debugger", "cookies", "history", "management", "privacy",
               "downloads", "clipboardRead", "declarativeNetRequestWithHostAccess", "scripting", "webNavigation", "contentSettings"}
BROAD = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
STORE_UPDATE = ("clients2.google.com", "edge.microsoft.com", "microsoftedge.microsoft.com")
KNOWN_SEARCH = ("google.", "bing.com", "duckduckgo.com", "yahoo.com", "ecosia.org", "brave.com", "startpage.com", "qwant.com", "{google:baseURL}")


def browser_roots():
    return [("Edge", os.path.join(LOCALAPPDATA, "Microsoft", "Edge", "User Data")),
            ("Chrome", os.path.join(LOCALAPPDATA, "Google", "Chrome", "User Data")),
            ("Brave", os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"))]


def browser_profiles():
    for b, ud in browser_roots():
        try:
            names = sorted(os.listdir(ud))
        except OSError:
            continue
        for n in names:
            p = os.path.join(ud, n)
            if (n == "Default" or n.startswith("Profile ")) and os.path.isfile(os.path.join(p, "Preferences")):
                yield b, n, p


def _dig(d, *ks):
    for k in ks:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def _msg(text, ext_dir, manifest):
    if not isinstance(text, str) or not text.startswith("__MSG_"):
        return text
    want = text[6:-2].lower()
    for loc in (manifest.get("default_locale"), "en", "en_US"):
        if loc:
            for k, v in load_json(os.path.join(ext_dir, "_locales", loc, "messages.json"), {}).items():
                if k.lower() == want and isinstance(v, dict):
                    return v.get("message", text)
    return text


def browser_findings():
    exts, homes, privacy = [], [], []
    for b, prof, p in browser_profiles():
        prefs = load_json(os.path.join(p, "Preferences"), {})
        sprefs = load_json(os.path.join(p, "Secure Preferences"), {})
        settings = dict(_dig(prefs, "extensions", "settings") or {})
        settings.update(_dig(sprefs, "extensions", "settings") or {})
        ed = os.path.join(p, "Extensions")
        try:
            ids = os.listdir(ed)
        except OSError:
            ids = []
        for eid in ids:
            st = settings.get(eid) or {}
            loc = st.get("location")
            if loc in (5, 10) or eid == "Temp":
                continue  # built-in component extensions
            try:
                vers = sorted(os.listdir(os.path.join(ed, eid)))
            except OSError:
                continue
            if not vers:
                continue
            xd = os.path.join(ed, eid, vers[-1])
            man = load_json(os.path.join(xd, "manifest.json"), {})
            if not man:
                continue
            perms = [x for x in (man.get("permissions") or []) + (man.get("host_permissions") or []) if isinstance(x, str)]
            for cs in man.get("content_scripts") or []:
                perms += [m for m in (cs.get("matches") or []) if isinstance(m, str)]
            perms = list(dict.fromkeys(perms))
            broad = [x for x in perms if x in BROAD]
            risky = [x for x in perms if x in RISKY_PERMS] + broad[:1]
            upd = str(man.get("update_url") or "")
            from_store = bool(st.get("from_webstore")) or any(h in upd for h in STORE_UPDATE)
            policy = loc in (6, 7, 8) or bool(st.get("installed_by_policy") or "")
            unpacked = loc == 4
            enabled = st.get("state", 1) == 1 and not st.get("disable_reasons")
            level = "high" if unpacked or (not from_store and not policy and (broad or len(risky) >= 2)) else \
                "medium" if broad or len(risky) >= 3 else "low"
            exts.append({"browser": b, "profile": prof, "id": eid, "name": _msg(man.get("name", eid), xd, man), "version": man.get("version", ""),
                         "risky": risky, "perms": len(perms), "from_store": from_store, "unpacked": unpacked, "policy": policy,
                         "enabled": enabled, "level": level, "path": xd})
        dsp = _dig(sprefs, "default_search_provider_data", "template_url_data", "url") or \
            _dig(prefs, "default_search_provider_data", "template_url_data", "url") or ""
        startup = [u for u in (_dig(prefs, "session", "startup_urls") or []) if isinstance(u, str)]
        home = prefs.get("homepage") or ""
        flags = []
        if dsp and not any(k in dsp for k in KNOWN_SEARCH):
            flags.append("unusual search engine")
        hp = startup + ([home] if home and prefs.get("homepage_is_newtabpage") is False else [])
        if any(u and not re.match(r"^(https?://)?([a-z0-9-]+\.)*(microsoft|msn|bing|google|office|office365|live|sharepoint)\.", u, re.I) for u in hp):
            flags.append("custom start/home page")
        homes.append({"browser": b, "profile": prof, "search": dsp or "(browser default)", "startup": startup[:5], "homepage": home, "flags": flags})
        cookies = os.path.join(p, "Network", "Cookies")
        files = {"History": os.path.join(p, "History"), "Cookies": cookies if os.path.exists(cookies) else os.path.join(p, "Cookies"),
                 "Form data": os.path.join(p, "Web Data"), "Top sites": os.path.join(p, "Top Sites"), "Visited links": os.path.join(p, "Visited Links")}
        sz = {k: (os.path.getsize(v) if os.path.isfile(v) else 0) for k, v in files.items()}
        privacy.append({"browser": b, "profile": prof, "sizes": sz, "total": sum(sz.values()), "path": p})
    return exts, homes, privacy


def hosts_findings():
    p = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows", "System32", "drivers", "etc", "hosts")
    out = []
    try:
        with open(p, "r", encoding="utf-8-sig", errors="replace") as f:
            for n, line in enumerate(f, 1):
                s = line.split("#", 1)[0].replace("\ufeff", "").strip()
                parts = s.split()
                if len(parts) < 2:
                    continue
                if len(parts) >= 2 and parts[1].lower() in ("localhost", "localhost.localdomain") and parts[0] in ("127.0.0.1", "::1"):
                    continue
                out.append({"line": n, "text": s})
    except OSError:
        pass
    return {"path": p, "entries": out}


def proxy_findings():
    v = reg_values("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") or {}
    return {"enabled": bool(v.get("ProxyEnable")), "server": str(v.get("ProxyServer") or ""), "pac": str(v.get("AutoConfigURL") or "")}


def av_decode(state):
    try:
        s = int(state)
    except (TypeError, ValueError):
        return {"on": None, "uptodate": None}
    return {"on": ((s >> 12) & 0xF) in (1, 3), "uptodate": ((s >> 4) & 0xF) == 0}


def defender_status():
    rows = ps_json("$o=[ordered]@{}; try { $m=Get-MpComputerStatus -EA Stop; $o.mp=[pscustomobject]@{ok=1; mode=[string]$m.AMRunningMode; av=[bool]$m.AntivirusEnabled; "
                   "rtp=[bool]$m.RealTimeProtectionEnabled; sig=[int64]$m.AntivirusSignatureAge; sigv=[string]$m.AntivirusSignatureVersion; qs=[int64]$m.QuickScanAge; "
                   "qsend=$(if($m.QuickScanEndTime){$m.QuickScanEndTime.ToString('s')}else{''}); tamper=[bool]$m.IsTamperProtected} } "
                   "catch { $o.mp=[pscustomobject]@{ok=0; err=$_.Exception.Message} }; "
                   "$o.av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -EA SilentlyContinue | ForEach-Object { "
                   "[pscustomobject]@{n=$_.displayName; s=$_.productState; p=$_.pathToSignedReportingExe} }); "
                   "try { $o.det=@(Get-MpThreatDetection -EA Stop | ForEach-Object { [pscustomobject]@{id=[string]$_.ThreatID; "
                   "t=$(if($_.InitialDetectionTime){$_.InitialDetectionTime.ToString('s')}else{''}); ok=[bool]$_.ActionSuccess; r=@($_.Resources)} }) } catch { $o.det=@() }; "
                   "try { $o.thr=@(Get-MpThreat -EA Stop | ForEach-Object { [pscustomobject]@{id=[string]$_.ThreatID; n=$_.ThreatName; sev=[int]$_.SeverityID; act=[bool]$_.IsActive} }) } "
                   "catch { $o.thr=@() }; [pscustomobject]$o", 90)
    d = rows[0] if rows and isinstance(rows[0], dict) else {}
    mp = d.get("mp") or {"ok": 0, "err": "Defender cmdlets are not available"}
    avs, seen = [], set()
    for a in d.get("av") or []:
        if isinstance(a, dict) and a.get("n") not in seen:
            seen.add(a.get("n"))
            avs.append({"name": a.get("n"), "path": a.get("p"), **av_decode(a.get("s"))})
    names = {t.get("id"): t for t in d.get("thr") or [] if isinstance(t, dict)}
    threats = []
    for t in d.get("det") or []:
        if isinstance(t, dict):
            th = names.get(t.get("id"), {})
            threats.append({"name": th.get("n") or f"Threat {t.get('id')}", "time": t.get("t"), "resolved": bool(t.get("ok")), "active": bool(th.get("act")),
                            "severity": th.get("sev"), "resources": [r for r in (t.get("r") or []) if isinstance(r, str)][:5]})
    active = bool(mp.get("ok") and mp.get("av") and str(mp.get("mode", "")).lower().startswith("normal"))
    other = [a["name"] for a in avs if a["on"] and "defender" not in str(a["name"]).lower()]
    note = ""
    if not active:
        note = ("Microsoft Defender is off or in passive mode because " + ", ".join(other) + " is the active antivirus. "
                "On a work PC your organization manages this, so the app doesn't change it.") if other else \
            "Microsoft Defender isn't running and no other antivirus reported itself to Windows Security Center."
    return {"mp": mp, "products": avs, "threats": threats, "defender_active": active, "other_av": other, "managed_note": note}


PROT = {"last": None}


def protection_job(job):
    job.progress.update(phase="defender", current="Antivirus status (Defender and Security Center)")
    av = defender_status()
    job.progress.update(phase="browsers", current="Browser extensions, home pages and search engines")
    exts, homes, privacy = browser_findings()
    job.progress.update(phase="startup", current="Startup items and scheduled tasks")
    st = startup_payload(True)["items"]
    tasks = [t for t in scheduled_tasks() if t["state"] != "Disabled"]
    texes = [exe_from_cmd(t["action"].split(" | ")[0]) for t in tasks]
    tsig = signatures([e for e in texes if e and suspicious_path(e)])
    sus_tasks = []
    for t, e in zip(tasks, texes):
        if suspicious_path(e):
            s = tsig.get(e, {"status": "Unknown", "signer": ""})
            sus_tasks.append({"name": t["name"], "path": t["path"], "action": t["action"], "exe": e, "signature": s["status"], "publisher": s["signer"],
                              "level": "low" if s["status"] == "Valid" else "high"})
    res = {"av": av, "extensions": exts, "homepages": homes, "privacy": privacy, "hosts": hosts_findings(), "proxy": proxy_findings(),
           "startup_flags": [i for i in st if i["suspicious"]], "tasks": sus_tasks, "time": time.strftime("%Y-%m-%d %H:%M")}
    res["summary"] = {"threats": sum(1 for t in av["threats"] if not t["resolved"]), "ext_high": sum(1 for e in exts if e["level"] == "high"),
                      "ext_medium": sum(1 for e in exts if e["level"] == "medium"), "extensions": len(exts), "startup": len(res["startup_flags"]),
                      "tasks": sum(1 for t in sus_tasks if t["level"] == "high"), "hosts": len(res["hosts"]["entries"]),
                      "search": sum(1 for h in homes if h["flags"])}
    PROT["last"] = res
    log_action("SCAN", f"Protection check (read-only): {json.dumps(res['summary'])}")
    return res


def quickscan_job(job):
    av = defender_status()
    if not av["defender_active"]:
        raise ValueError(av["managed_note"] or "Microsoft Defender isn't the active antivirus, so a Defender scan can't run.")
    log_action("PROTECT", "Started a Microsoft Defender Quick Scan (read-only scan)")
    job.progress.update(phase="scanning", current="Defender Quick Scan")
    t0 = time.time()
    p = subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-Command", "Start-MpScan -ScanType QuickScan"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=NO_WINDOW_FLAG)
    while p.poll() is None:
        if job.cancel.is_set() or time.time() - t0 > 600:
            return {"done": False, "note": "Stopped waiting after 10 minutes; Defender keeps scanning in the background.", "seconds": int(time.time() - t0)}
        time.sleep(1)
    av = defender_status()
    log_action("PROTECT", f"Defender Quick Scan finished in {int(time.time() - t0)}s; {len(av['threats'])} detection(s) in history")
    return {"done": True, "seconds": int(time.time() - t0), "threats": av["threats"]}


# ---------------------------------------------------------------- winget (updater)
WINGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-_+]{1,127}$")
WINGET = {"last": None}


def winget_exe():
    w = shutil.which("winget")
    if w:
        return w
    if IS_WIN:
        p = os.path.join(LOCALAPPDATA, "Microsoft", "WindowsApps", "winget.exe")
        return p if os.path.exists(p) else None
    return None


def parse_winget(text):
    lines = [ln.split("\r")[-1].rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    hi = next((i for i, ln in enumerate(lines) if re.search(r"\bName\b", ln) and re.search(r"\bId\b", ln) and "Available" in ln), None)
    if hi is None:
        return []
    h = lines[hi]
    off = h.index("Name")
    cols = [(m.start(), m.group()) for m in re.finditer(r"\S+", h[off:])]
    out = []
    for ln in lines[hi + 1:]:
        ln = ln[off:] if len(ln) > off and not ln[:off].strip() else ln
        if not ln.strip() or set(ln.strip()) <= set("-"):
            continue
        if re.match(r"^\d+ (upgrades?|packages?)", ln.strip()) or ln.startswith("The following") or "require explicit" in ln:
            break
        row = {}
        for j, (st, name) in enumerate(cols):
            en = cols[j + 1][0] if j + 1 < len(cols) else None
            row[name] = (ln[st:en] if en else ln[st:]).strip()
        if row.get("Id") and row.get("Available"):
            out.append({"name": row.get("Name", ""), "id": row["Id"], "version": row.get("Version", ""), "available": row["Available"],
                        "source": row.get("Source", ""), "applyable": bool(WINGET_ID.match(row["Id"]))})
    return out


def winget_job(job):
    exe = winget_exe()
    if not exe:
        raise ValueError("winget (App Installer) isn't available on this PC")
    job.progress.update(phase="winget", current="Checking for app updates (winget, read-only)")
    r = subprocess.run([exe, "upgrade", "--source", "winget", "--disable-interactivity"], capture_output=True, timeout=240, creationflags=NO_WINDOW_FLAG)
    text = r.stdout.decode("utf-8", "replace")
    items = parse_winget(text)
    note = "" if items or re.search(r"No (installed package|available upgrade)", text) else text.strip()[-300:]
    WINGET["last"] = {"items": items, "time": time.strftime("%Y-%m-%d %H:%M"), "note": note}
    log_action("SCAN", f"winget update check (read-only): {len(items)} upgrade(s) available")
    return WINGET["last"]


# Source: winget-cli doc/windows/package-manager/winget/returnCodes.md (codes are HRESULTs 0x8A15xxxx)
WINGET_CODES = {
    0x8A150001: ("Internal error", "winget hit an internal error. Try again; if it repeats, update App Installer from the Microsoft Store."),
    0x8A150003: ("Executing command failed", "winget couldn't finish the command. Try again in a minute."),
    0x8A150006: ("Running ShellExecute failed", "The app's own installer failed or was cancelled. This usually means it needs admin approval (UAC), "
                 "the app is open, or your organization blocks it. Close the app and try again with Relaunch as admin, or update it from the app itself."),
    0x8A150008: ("Downloading installer failed", "The download failed. Check your internet connection and try again."),
    0x8A150010: ("No applicable installer", "None of this package's installers fit this PC (architecture, scope or Windows version)."),
    0x8A150011: ("Installer hash mismatch", "The downloaded installer didn't match winget's checksum, so it wasn't run. Try again later."),
    0x8A150014: ("No packages found", "winget couldn't find that package any more."),
    0x8A150019: ("Command requires admin", "This upgrade needs admin rights. Use Relaunch as admin and try again."),
    0x8A15002B: ("No applicable update found", "winget says no newer version fits this install. Often the app updates itself."),
    0x8A15002D: ("Installer failed security check", "Windows security blocked the installer."),
    0x8A150041: ("Package agreements not accepted", "The package's license wasn't accepted."),
    0x8A15003A: ("Blocked by Group Policy", "Your organization's policy blocks this. Contact IT."),
    0x8A15004F: ("Upgrade version not newer", "The available version isn't newer than what you have."),
    0x8A150056: ("Installer prohibits elevation", "This installer can't run as admin. Try again without Relaunch as admin."),
    0x8A150061: ("Package already installed", "A version is already installed; nothing to do."),
    0x8A150068: ("Package is pinned", "This package is pinned in winget, which prevents upgrades."),
    0x8A15006D: ("Service unavailable", "A required service is busy. Try again later."),
    0x8A15008E: ("Install technology mismatch", "The update uses a different installer type than your current install. Update it from the app or its website."),
    0x8A150101: ("Application is running", "Close the app, then try again."),
    0x8A150102: ("Another install in progress", "Another installation is running. Try again when it finishes."),
    0x8A150103: ("File in use", "One or more of its files are in use. Close the app and try again."),
    0x8A150104: ("Missing dependency", "This package needs something that isn't installed."),
    0x8A150105: ("Disk full", "There isn't enough free space. Free some space and try again."),
    0x8A150107: ("No network", "The installer needs internet access."),
    0x8A150108: ("Installer error", "The app's installer reported an error. Contact the app's support or update it from its website."),
    0x8A150109: ("Restart required to finish", "Restart your PC to finish the update."),
    0x8A15010A: ("Restart required first", "Restart your PC, then try again."),
    0x8A15010C: ("Cancelled", "The installation was cancelled."),
    0x8A15010E: ("Downgrade", "A newer version is already installed."),
    0x8A15010F: ("Blocked by policy", "Your organization blocks installing this. Contact IT."),
    0x8A150111: ("In use by another app", "Another app is using it. Close other apps and try again."),
    0x8A150114: ("Upgrade not supported", "This installer can't upgrade in place. Uninstall and reinstall, or update from the app."),
    0x8A150115: ("Custom installer error", "The app's installer failed with its own error code."),
}


def winget_explain(code):
    """Friendly text for a winget exit code (works for signed or unsigned 32-bit values)."""
    try:
        c = int(code) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return {"code": code, "hex": "", "title": "Unknown result", "message": ""}
    hx = f"0x{c:08X}"
    if c == 0:
        return {"code": 0, "hex": hx, "title": "Updated", "message": "The upgrade finished."}
    t, m = WINGET_CODES.get(c, ("winget error" if (c >> 16) == 0x8A15 else "Installer exit code",
                                "winget reported an error. Open the Activity log for details." if (c >> 16) == 0x8A15
                                else "The app's installer returned this code. Try again, or update the app from its own updater."))
    return {"code": c, "hex": hx, "title": t, "message": m}


WINGET_FAIL_FILE = os.path.join(DATA_DIR, "winget-failures.json")


def winget_failures():
    if not os.path.exists(WINGET_FAIL_FILE):  # first run of v3: learn earlier failures from the activity log
        f = {}
        for ln in reversed(read_log(2000)) if os.path.exists(LOG_FILE) else []:
            m = re.search(r"winget upgrade (\S+): exit (-?\d+)", ln.get("msg", "") if isinstance(ln, dict) else str(ln))
            if m:
                ex = winget_explain(m.group(2))
                if ex["code"]:
                    f[m.group(1)] = {**ex, "time": (ln.get("time", "") if isinstance(ln, dict) else "")}
                else:
                    f.pop(m.group(1), None)
        try:
            save_json(WINGET_FAIL_FILE, f)
        except OSError:
            pass
        return f
    d = load_json(WINGET_FAIL_FILE, {})
    return d if isinstance(d, dict) else {}


def winget_upgrade_job(job, pkg_id):
    exe = winget_exe()
    job.progress.update(phase="upgrade", current=pkg_id)
    log_action("UPDATE", f"winget upgrade {pkg_id} started")
    r = subprocess.run([exe, "upgrade", "--id", pkg_id, "--exact", "--source", "winget", "--disable-interactivity",
                        "--accept-package-agreements", "--accept-source-agreements"], capture_output=True, timeout=3600, creationflags=NO_WINDOW_FLAG)
    tail = [t.split("\r")[-1] for t in r.stdout.decode("utf-8", "replace").strip().split("\n")[-3:]]
    ex = winget_explain(r.returncode)
    log_action("UPDATE", f"winget upgrade {pkg_id}: exit {ex['code']} ({ex['hex']} {ex['title']})")
    f = winget_failures()
    if ex["code"]:
        f[pkg_id] = {**ex, "time": time.strftime("%Y-%m-%d %H:%M")}
    else:
        f.pop(pkg_id, None)
    save_json(WINGET_FAIL_FILE, f)
    return {"id": pkg_id, "code": ex["code"], "hex": ex["hex"], "title": ex["title"], "message": ex["message"], "ok": ex["code"] == 0, "tail": tail}


# ---------------------------------------------------------------- health: disks, battery, Windows Update (read-only)
def battery_report():
    if not IS_WIN:
        return None
    os.makedirs(CACHE_DIR, exist_ok=True)
    f = os.path.join(CACHE_DIR, "battery-report.xml")
    try:
        subprocess.run(["powercfg", "/batteryreport", "/xml", "/output", f], capture_output=True, timeout=60, creationflags=NO_WINDOW_FLAG)
        root = ET.parse(f).getroot()
    except Exception:
        return None
    for el in root.iter():
        if el.tag.split("}")[-1] == "Battery":
            g = {c.tag.split("}")[-1]: (c.text or "") for c in el}
            try:
                des, full = int(g.get("DesignCapacity", 0)), int(g.get("FullChargeCapacity", 0))
            except ValueError:
                des = full = 0
            return {"name": g.get("Id", ""), "maker": g.get("ManufactureName", ""), "design": des, "full": full,
                    "health": round(full / des * 100) if des else None, "cycles": g.get("CycleCount", ""), "chem": g.get("Chemistry", "")}
    return None


def health_info(force=False):
    def q():
        rows = ps_json("$o=[ordered]@{}; $o.disks=@(Get-PhysicalDisk -EA SilentlyContinue | ForEach-Object { $r=$null; try { $r = $_ | Get-StorageReliabilityCounter -EA Stop } catch {}; "
                       "[pscustomobject]@{n=$_.FriendlyName; m=[string]$_.MediaType; h=[string]$_.HealthStatus; o=[string]($_.OperationalStatus -join ','); s=[int64]$_.Size; "
                       "b=[string]$_.BusType; t=$(if($r){$r.Temperature}else{$null}); w=$(if($r){$r.Wear}else{$null}); rel=[bool]$r} }); "
                       "try { $s=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $n=$s.GetTotalHistoryCount(); "
                       "$o.wu=@($s.QueryHistory(0,[Math]::Min(60,$n)) | Where-Object { $_.Title } | ForEach-Object { [pscustomobject]@{t=$_.Title; d=$_.Date.ToLocalTime().ToString('s'); r=[int]$_.ResultCode} }) } "
                       "catch { $o.wu=@(Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 6 | ForEach-Object { "
                       "[pscustomobject]@{t=$_.HotFixID + ' ' + $_.Description; d=$(if($_.InstalledOn){$_.InstalledOn.ToString('s')}else{''}); r=2} }) }; [pscustomobject]$o", 120)
        d = rows[0] if rows and isinstance(rows[0], dict) else {}
        disks = [{"name": x.get("n"), "media": x.get("m"), "health": x.get("h"), "status": x.get("o"), "size": x.get("s"), "bus": x.get("b"),
                  "temp": x.get("t"), "wear": x.get("w"), "reliability": bool(x.get("rel"))} for x in d.get("disks") or [] if isinstance(x, dict)]
        wu = [{"title": x.get("t"), "date": x.get("d"), "ok": x.get("r") == 2} for x in d.get("wu") or [] if isinstance(x, dict)]
        # Store app updates ("9PLM9XGG6VKS-OpenAI.Codex") crowd out Windows updates; show Windows ones first
        store = re.compile(r"^[0-9A-Z]{12}-")
        wu = ([x for x in wu if not store.match(x["title"] or "")] + [x for x in wu if store.match(x["title"] or "")])[:8]
        reboot = []
        if reg_exists("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", V64):
            reboot.append("Windows Update needs a restart")
        if reg_exists("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", V64):
            reboot.append("A Windows component install needs a restart")
        return {"disks": disks, "updates": wu, "reboot": reboot, "battery": battery_report(), "admin": is_admin(), "time": time.strftime("%H:%M")}
    return cached("health", 600, q, force)


# ---------------------------------------------------------------- live monitor (ctypes + one typeperf + one nvidia-smi process, only while watched)
class FILETIME(ctypes.Structure):
    _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]


def _ft(f):
    return (f.hi << 32) | f.lo


class MEMSTAT(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_uint32), ("dwMemoryLoad", ctypes.c_uint32), ("total", ctypes.c_uint64), ("avail", ctypes.c_uint64),
                ("totalPage", ctypes.c_uint64), ("availPage", ctypes.c_uint64), ("totalVirt", ctypes.c_uint64), ("availVirt", ctypes.c_uint64),
                ("availExt", ctypes.c_uint64)]


class SPPI(ctypes.Structure):
    _fields_ = [("idle", ctypes.c_int64), ("kernel", ctypes.c_int64), ("user", ctypes.c_int64), ("dpc", ctypes.c_int64),
                ("intr", ctypes.c_int64), ("count", ctypes.c_uint32)]


class POWERSTAT(ctypes.Structure):
    _fields_ = [("ac", ctypes.c_ubyte), ("flag", ctypes.c_ubyte), ("pct", ctypes.c_ubyte), ("saver", ctypes.c_ubyte),
                ("life", ctypes.c_uint32), ("full", ctypes.c_uint32)]


class Monitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.hist, self.last, self.io = [], {}, {}
        self.prev_sys = self.prev_core = None
        self.gpu = self.temps = None
        self.running = False
        self.last_req = 0
        self.ncpu = os.cpu_count() or 1

    def alive(self):
        return time.time() - self.last_req < 30

    def touch(self):
        self.last_req = time.time()
        with self.lock:
            if self.running:
                return
            self.running = True
        threading.Thread(target=self.loop, daemon=True).start()
        if IS_WIN:
            threading.Thread(target=self.typeperf, daemon=True).start()
            threading.Thread(target=self.nvsmi, daemon=True).start()
            if self.temps is None:
                threading.Thread(target=self.read_temps, daemon=True).start()

    def loop(self):
        try:
            while self.alive():
                try:
                    s = self.sample()
                    with self.lock:
                        self.last = s
                        self.hist.append({"t": s["t"], "cpu": s["cpu"], "mem": s["mem_pct"], "rd": s["disk_read"], "wr": s["disk_write"],
                                          "rx": s["net_rx"], "tx": s["net_tx"], "gpu": (s["gpu"] or {}).get("util")})
                        self.hist = self.hist[-120:]
                except Exception as e:
                    self.last = {"error": str(e), "t": time.time()}
                time.sleep(1)
        finally:
            self.running = False

    def cpu(self):
        if not IS_WIN:
            return 0.0, []
        i, k, u = FILETIME(), FILETIME(), FILETIME()
        ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
        cur = (_ft(i), _ft(k), _ft(u))
        tot = 0.0
        if self.prev_sys:
            di, dk, du = (cur[0] - self.prev_sys[0]), (cur[1] - self.prev_sys[1]), (cur[2] - self.prev_sys[2])
            tot = max(0.0, min(100.0, (dk + du - di) / max(1, dk + du) * 100))  # kernel time includes idle
        self.prev_sys = cur
        arr = (SPPI * self.ncpu)()
        ret = ctypes.c_uint32()
        cores = []
        if ctypes.windll.ntdll.NtQuerySystemInformation(8, ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(ret)) == 0:
            now = [(a.idle, a.kernel, a.user) for a in arr]
            if self.prev_core:
                for (i0, k0, u0), (i1, k1, u1) in zip(self.prev_core, now):
                    t = (k1 - k0) + (u1 - u0)
                    cores.append(round(max(0.0, min(100.0, (t - (i1 - i0)) / max(1, t) * 100)), 1))
            self.prev_core = now
        return round(tot, 1), cores

    def sample(self):
        cpu, cores = self.cpu()
        mem = {"total": 0, "avail": 0, "load": 0}
        bat, up = None, 0
        if IS_WIN:
            m = MEMSTAT()
            m.dwLength = ctypes.sizeof(m)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            mem = {"total": m.total, "avail": m.avail, "load": m.dwMemoryLoad, "commit": m.totalPage - m.availPage, "commit_limit": m.totalPage}
            ps = POWERSTAT()
            if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(ps)) and not ps.flag & 128 and ps.flag != 255:
                bat = {"pct": None if ps.pct == 255 else ps.pct, "ac": ps.ac == 1, "charging": bool(ps.flag & 8),
                       "secs_left": None if ps.life == 0xFFFFFFFF else ps.life}
            ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_uint64
            up = ctypes.windll.kernel32.GetTickCount64() // 1000
        io = dict(self.io)
        disks = drives()
        for d in disks:
            k = d["root"].rstrip("\\")
            d["read"], d["write"] = io.get(("disk_r", k), 0), io.get(("disk_w", k), 0)
        nets = {}
        for (kind, inst), v in io.items():
            if kind in ("net_rx", "net_tx"):
                nets.setdefault(inst, {"name": inst, "rx": 0, "tx": 0})[kind[4:]] = v
        return {"t": time.time(), "cpu": cpu, "cores": cores, "mem_total": mem["total"], "mem_avail": mem["avail"], "mem_pct": mem["load"],
                "commit": mem.get("commit", 0), "commit_limit": mem.get("commit_limit", 0), "disks": disks,
                "disk_read": io.get(("disk_r", "_Total"), 0), "disk_write": io.get(("disk_w", "_Total"), 0),
                "nets": sorted(nets.values(), key=lambda x: -(x["rx"] + x["tx"])),
                "net_rx": sum(n["rx"] for n in nets.values()), "net_tx": sum(n["tx"] for n in nets.values()),
                "gpu": self.gpu, "temps": self.temps, "battery": bat, "uptime": up, "ncpu": self.ncpu, "io_ready": bool(io)}

    def typeperf(self):
        cmd = ["typeperf", r"\LogicalDisk(*)\Disk Read Bytes/sec", r"\LogicalDisk(*)\Disk Write Bytes/sec",
               r"\Network Interface(*)\Bytes Received/sec", r"\Network Interface(*)\Bytes Sent/sec", "-si", "1"]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=NO_WINDOW_FLAG, text=True, errors="replace")
        except OSError:
            return
        hdr = None
        try:
            for line in p.stdout:
                if not self.alive():
                    break
                if not line.startswith('"'):
                    continue
                row = next(csv.reader([line.strip()]))
                if row and row[0].startswith("(PDH-CSV"):
                    hdr = []
                    for c in row[1:]:
                        m = re.search(r"\\(LogicalDisk|Network Interface)\((.*)\)\\(.+)$", c)
                        if not m:
                            hdr.append(None)
                            continue
                        obj, inst, ctr = m.groups()
                        kind = ("disk_r" if "Read" in ctr else "disk_w") if obj == "LogicalDisk" else ("net_rx" if "Received" in ctr else "net_tx")
                        hdr.append((kind, inst))
                    continue
                if not hdr:
                    continue
                io = {}
                for k, v in zip(hdr, row[1:]):
                    if k and not (k[0].startswith("net") and re.search(r"(?i)isatap|teredo|loopback|pseudo", k[1])):
                        try:
                            io[k] = float(v)
                        except ValueError:
                            pass
                self.io = io
        finally:
            p.kill()
            self.io = {}

    def nvsmi(self):
        exe = shutil.which("nvidia-smi") or os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "nvidia-smi.exe")
        if not os.path.isfile(exe):
            return
        try:
            p = subprocess.Popen([exe, "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
                                  "--format=csv,noheader,nounits", "-lms", "2000"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 creationflags=NO_WINDOW_FLAG, text=True, errors="replace")
        except OSError:
            return

        def num(x):
            return float(x) if re.fullmatch(r"[\d.]+", x or "") else None
        try:
            for line in p.stdout:
                if not self.alive():
                    break
                f = [x.strip() for x in line.split(",")]
                if len(f) >= 5:
                    self.gpu = {"name": f[0], "util": num(f[1]), "mem_used": (num(f[2]) or 0) * 2 ** 20, "mem_total": (num(f[3]) or 0) * 2 ** 20,
                                "temp": num(f[4]), "power": num(f[5]) if len(f) > 5 else None}
        finally:
            p.kill()

    def read_temps(self):
        rows = ps_json("try { Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -EA Stop | ForEach-Object { "
                       "[pscustomobject]@{n=$_.InstanceName; c=[math]::Round($_.CurrentTemperature/10 - 273.15,1)} } } catch { [pscustomobject]@{err=$_.Exception.Message} }", 40)
        z = [{"name": r.get("n"), "c": r.get("c")} for r in rows if isinstance(r, dict) and r.get("n")]
        err = next((r.get("err") for r in rows if isinstance(r, dict) and r.get("err")), "")
        self.temps = {"zones": z, "note": "" if z else f"CPU temperature isn't readable on this PC ({(err or 'no thermal zones').strip()}). GPU temperature comes from nvidia-smi."}

    def payload(self):
        self.touch()
        with self.lock:
            return {"now": self.last, "hist": self.hist[-90:]}


MON = Monitor()


# ---------------------------------------------------------------- processes (Toolhelp snapshot + GetProcessTimes + K32GetProcessMemoryInfo)
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("heap", ctypes.c_size_t),
                ("mod", ctypes.c_uint32), ("threads", ctypes.c_uint32), ("ppid", ctypes.c_uint32), ("pri", ctypes.c_long),
                ("flags", ctypes.c_uint32), ("exe", ctypes.c_wchar * 260)]


class PMC(ctypes.Structure):
    _fields_ = [("cb", ctypes.c_uint32), ("faults", ctypes.c_uint32), ("peakWS", ctypes.c_size_t), ("ws", ctypes.c_size_t),
                ("a", ctypes.c_size_t), ("b", ctypes.c_size_t), ("c", ctypes.c_size_t), ("d", ctypes.c_size_t),
                ("page", ctypes.c_size_t), ("peakPage", ctypes.c_size_t), ("private", ctypes.c_size_t)]


CRITICAL = {"system", "idle", "[system process]", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe", "smss.exe", "svchost.exe",
            "fontdrvhost.exe", "dwm.exe", "registry", "memory compression", "secure system", "lsaiso.exe", "msmpeng.exe", "sedservice.exe", "explorer.exe"}
_PREV_CPU = {}


def _k32_setup():
    K32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    K32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    K32.Process32FirstW.argtypes = K32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    K32.OpenProcess.restype = ctypes.c_void_p
    K32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    K32.CloseHandle.argtypes = [ctypes.c_void_p]
    K32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(FILETIME)] * 4
    K32.K32GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(PMC), ctypes.c_uint32]
    K32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]


def list_processes():
    if not IS_WIN:
        return []
    _k32_setup()
    snap = K32.CreateToolhelp32Snapshot(2, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
        return []
    out, now, ncpu = [], time.time(), os.cpu_count() or 1
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = K32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            pid, name = e.pid, e.exe
            mem, cpu, created = 0, 0.0, 0
            h = K32.OpenProcess(0x1000, False, pid) if pid else None
            if h:
                try:
                    c, x, k, u = FILETIME(), FILETIME(), FILETIME(), FILETIME()
                    if K32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(x), ctypes.byref(k), ctypes.byref(u)):
                        created = _ft(c)
                        busy = _ft(k) + _ft(u)
                        prev = _PREV_CPU.get(pid)
                        if prev and prev[0] == created and now > prev[2]:
                            cpu = max(0.0, (busy - prev[1]) / 1e7 / (now - prev[2]) / ncpu * 100)
                        _PREV_CPU[pid] = (created, busy, now)
                    pm = PMC()
                    pm.cb = ctypes.sizeof(pm)
                    if K32.K32GetProcessMemoryInfo(h, ctypes.byref(pm), pm.cb):
                        mem = pm.private or pm.ws
                finally:
                    K32.CloseHandle(h)
            out.append({"pid": pid, "name": name, "cpu": round(cpu, 1), "mem": mem, "threads": e.threads, "created": str(created),
                        "critical": name.lower() in CRITICAL or pid in (0, 4) or pid == os.getpid()})
            ok = K32.Process32NextW(snap, ctypes.byref(e))
    finally:
        K32.CloseHandle(snap)
    return out


def end_process(pid, name, created):
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        raise ValueError("bad pid")
    p = next((x for x in list_processes() if x["pid"] == pid), None)
    if not p or p["name"] != name or p["created"] != str(created):
        raise ValueError("That process has already exited or changed")
    if p["critical"]:
        raise ValueError(f"{name} is a protected Windows process and can't be ended here")
    h = K32.OpenProcess(0x0001, False, pid)
    if not h:
        raise ValueError("Windows refused (it may need admin)")
    try:
        ok = K32.TerminateProcess(h, 1)
    finally:
        K32.CloseHandle(h)
    log_action("END TASK", f"Ended {name} (PID {pid})" + ("" if ok else " - failed"))
    return {"ok": bool(ok)}


# ---------------------------------------------------------------- admin relaunch (UAC prompt; never automatic)
SERVER = [None]


def relaunch_admin():
    if is_admin():
        raise ValueError("Already running as admin")
    if not IS_WIN:
        raise ValueError("Windows only")
    exe = sys.executable
    if exe.lower().endswith("python.exe") and os.path.exists(exe[:-10] + "pythonw.exe"):
        exe = exe[:-10] + "pythonw.exe"
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, f'"{os.path.abspath(__file__)}" --elevated --no-window', APP_DIR, 1)
    if rc <= 32:
        raise ValueError("Admin relaunch was cancelled")
    log_action("ADMIN", "Relaunching as admin (UAC approved); this window reconnects automatically")
    threading.Timer(1.0, lambda: SERVER[0] and SERVER[0].shutdown()).start()
    return {"ok": True}


# ---------------------------------------------------------------- dashboard: Smart Scan (read-only)
SMART = {"last": None}


def downloads_summary(job=None, cap_s=75):
    """Read-only summary of Downloads: old files (names, sizes, ages; never contents), biggest subfolders, old installers.
    OneDrive cloud-only placeholders are counted separately and never opened or hydrated."""
    days = int(load_settings().get("old_days", 90) or 90)
    now = time.time()
    cut = now - days * 86400
    t0 = now
    old, folders = [], {}
    cloud_n = cloud_b = files = 0
    partial, src = False, "walk"

    def add_old(path, size, mt):
        old.append((size, path, mt))
        rel = os.path.relpath(path, DOWNLOADS)
        top = rel.split(os.sep)[0] if os.sep in rel else "(loose files)"
        f = folders.setdefault(top, [0, 0])
        f[0] += size; f[1] += 1
    r = SCAN["result"]
    if r and r["stats"].get("downloads_recursive"):
        src = "scan"
        for x in r["downloads"]:
            files += 1
            if x["cloud"]:
                cloud_n += 1; cloud_b += x["size"]
            elif not x["protected"] and x["mtime"] < cut:
                add_old(x["path"], x["size"], x["mtime"])
    elif os.path.isdir(DOWNLOADS):
        stack = [DOWNLOADS]
        while stack:
            if job is not None and job.cancel.is_set():
                return None
            if time.time() - t0 > cap_s:
                partial = True
                break
            d = stack.pop()
            if fast_protected(d):
                continue
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                        if e.is_dir(follow_symlinks=False):
                            if not skip_dir_entry(e, st):
                                stack.append(e.path)
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    files += 1
                    if is_cloud(st):
                        cloud_n += 1; cloud_b += st.st_size
                        continue
                    if st.st_size >= OLD_MIN and st.st_mtime < cut:
                        add_old(e.path, st.st_size, st.st_mtime)
            if job is not None and files % 2000 < 50:
                job.progress["current"] = f"Downloads folder: {files:,} files read"
    top = heapq.nlargest(12, old)
    try:
        inst = downloads_installers()
    except Exception:
        inst = {"count": 0, "size": 0, "items": []}
    return {"folder": DOWNLOADS, "days": days, "old_count": len(old), "old_size": sum(x[0] for x in old), "files": files,
            "cloud_count": cloud_n, "cloud_size": cloud_b, "partial": partial, "source": src, "seconds": round(time.time() - t0, 1),
            "top_old": [{"path": p, "name": os.path.basename(p), "size": s, "age_days": int((now - m) / 86400)} for s, p, m in top],
            "top_folders": [{"name": k, "size": v[0], "files": v[1]} for k, v in sorted(folders.items(), key=lambda kv: -kv[1][0])[:6]],
            "installers": {k: inst.get(k) for k in ("count", "size", "days")} | {"top": [{"path": x["path"], "name": os.path.basename(x["path"]), "size": x["size"],
                                                                                     "age_days": x["age_days"]} for x in (inst.get("items") or [])[:10]]}}


def last_scan_summary():
    return scan_summary(int(load_settings().get("old_days", 90) or 90)) if SCAN["result"] else load_json(SCAN_SUMMARY_FILE, None)


def space_summary(c, dl, ss):
    """'Space you could free': safe-to-clean caches, the Recycle Bin, and things worth reviewing (may overlap)."""
    items = []
    for x in (c or {}).get("cats") or []:
        if not x.get("size"):
            continue
        kind = "review" if x.get("review_only") else "optin" if x.get("optin") else "clean"
        note = "close the browser first" if x.get("running") else "needs admin, clean via Windows Storage settings" if x.get("review_only") else \
            "opt-in" if x.get("optin") else f"{x.get('files', 0):,} files"
        items.append({"id": x["id"], "label": x["name"], "size": x["size"], "kind": kind, "tab": "cleanup", "note": note,
                      "default": bool(x.get("default")) and not x.get("running")})
    rb = (c or {}).get("recycle") or {}
    if rb.get("size"):
        items.append({"id": "bin", "label": "Recycle Bin", "size": rb["size"], "kind": "permanent", "tab": "cleanup",
                      "note": f"{rb.get('items', 0):,} items, emptying is permanent"})
    if ss and ss.get("dup_waste"):
        items.append({"id": "dups", "label": "Extra duplicate copies", "size": ss["dup_waste"], "kind": "review", "tab": "scan", "sub": "dups",
                      "note": f"{ss.get('dup_groups', 0)} sets, scan {ss.get('time', '')}"})
    if dl and dl.get("old_size"):
        items.append({"id": "olddl", "label": f"Downloads older than {dl['days']} days", "size": dl["old_size"], "kind": "review", "tab": "scan", "sub": "old",
                      "note": f"{dl['old_count']:,} files" + (" (partial count)" if dl.get("partial") else "")})
    inst = (dl or {}).get("installers") or ((c or {}).get("installers") or {})
    if inst.get("size"):
        items.append({"id": "installers", "label": "Old installers in Downloads", "size": inst["size"], "kind": "info", "tab": "cleanup",
                      "note": f"{inst.get('count', 0)} .exe/.msi files older than 30 days (part of old Downloads)"})
    items.sort(key=lambda x: -x["size"])
    clean = sum(x["size"] for x in items if x["kind"] in ("clean", "optin"))
    safe = sum(x["size"] for x in items if x["kind"] == "clean" and x.get("default"))
    binsz = sum(x["size"] for x in items if x["kind"] == "permanent")
    review = sum(x["size"] for x in items if x["kind"] == "review")
    return {"items": items, "safe_now": safe, "clean": clean, "bin": binsz, "review": review, "total": clean + binsz + review,
            "note": "Duplicates and old Downloads can overlap, so the review total is an upper estimate. Cloud-only OneDrive files are never counted."}


def smart_job(job):
    res = {}
    steps = [("cleanup", "Junk and caches"), ("downloads", "Downloads folder (names, sizes and dates only)"), ("startup", "Startup items"),
             ("protection", "Protection checks"), ("apps", "Installed programs"), ("health", "Disk, battery and Windows Update"), ("updates", "App updates (winget)")]
    for i, (k, label) in enumerate(steps):
        if job.cancel.is_set():
            return None
        job.progress.update(phase=k, step=i + 1, steps=len(steps), current=label)
        try:
            if k == "cleanup":
                res[k] = measure_job(Job("measure"))
            elif k == "downloads":
                res[k] = downloads_summary(job)
            elif k == "startup":
                sp = startup_payload(True)
                res[k] = {kk: v for kk, v in sp.items() if kk != "items"}
                res[k]["notable"] = [{"id": x["id"], "name": x["name"], "kind": x["kind"], "enabled": x["enabled"], "can_toggle": x["can_toggle"],
                                      "impact": x.get("impact"), "signature": x.get("signature"), "broken": x.get("broken"), "why": x.get("broken_reason", ""),
                                      "suspicious": x.get("suspicious"), "publisher": x.get("publisher", "")}
                                     for x in sp["items"] if x["enabled"] and (x.get("broken") or x.get("suspicious") or x.get("impact") == "high")][:25]
            elif k == "protection":
                p = protection_job(Job("prot"))
                res[k] = {"summary": p["summary"], "defender_active": p["av"]["defender_active"], "products": p["av"]["products"],
                          "managed_note": p["av"]["managed_note"], "threats": p["av"]["threats"][:10],
                          "extensions": [{"name": e["name"], "browser": e["browser"], "level": e["level"], "enabled": e["enabled"]}
                                         for e in p["extensions"] if e["level"] != "low" or re.search(r"mcafee|norton|avast|avg|webadvisor|safe ?search", e["name"] or "", re.I)][:15]}
            elif k == "apps":
                pp = programs_payload(True)
                res[k] = {"count": pp["count"], "av_programs": [{"id": x["id"], "name": x["name"], "publisher": x.get("publisher", "")}
                                                                for x in pp.get("programs") or [] if re.search(r"mcafee|norton|avast|avg |kaspersky|webadvisor", x["name"] or "", re.I)][:10]}
            elif k == "health":
                res[k] = health_info(True)
            elif k == "updates":
                w = winget_job(Job("winget")) if winget_exe() else {"items": [], "note": "winget not found"}
                res[k] = {"count": len(w["items"]), "items": w["items"][:45], "note": w.get("note", "")}
        except Exception as e:
            res[k] = {"error": str(e)}
    res["drives"] = drives()
    res["scan"] = SCAN["result"]["stats"] if SCAN["result"] else None
    res["scan_summary"] = last_scan_summary()
    res["time"] = time.strftime("%Y-%m-%d %H:%M")
    res["admin"] = is_admin()
    res["score"], res["issues"] = health_score(res)
    res["space"] = space_summary(res.get("cleanup"), res.get("downloads"), res.get("scan_summary"))
    res["reclaimable"] = res["space"]["total"]
    SMART["last"] = res
    RECS["last"] = None
    save_json(SMART_FILE, res)
    log_action("SCAN", f"Smart Scan (read-only): health {res['score']}/100, {len(res['issues'])} item(s) to review, "
                       f"{fmt(res['space']['total'])} you could free ({fmt(res['space']['clean'] + res['space']['bin'])} cleanable)")
    return res


def health_score(r):
    s, issues = 100, []

    def hit(pts, text, tab, sev="warn"):
        nonlocal s
        s -= pts
        issues.append({"text": text, "tab": tab, "sev": sev})
    for d in r.get("drives") or []:
        if d["total"] and d["free"] / d["total"] < 0.10:
            hit(15, f"{d['root']} is almost full ({fmt(d['free'])} free)", "scan", "bad")
        elif d["total"] and d["free"] / d["total"] < 0.20:
            hit(6, f"{d['root']} is getting full ({fmt(d['free'])} free)", "scan")
    c = r.get("cleanup") or {}
    junk = sum(x["size"] for x in c.get("cats") or [] if not x.get("review_only")) + (c.get("recycle") or {}).get("size", 0)
    if junk > 5 * 2 ** 30:
        hit(8, f"{fmt(junk)} of temp files, caches and Recycle Bin can be cleaned", "cleanup")
    p = r.get("protection") or {}
    sm = p.get("summary") or {}
    if p and not p.get("error") and not p.get("defender_active") and not any(x.get("on") for x in p.get("products") or []):
        hit(25, "No active antivirus was found", "protection", "bad")
    if sm.get("threats"):
        hit(25, f"{sm['threats']} unresolved threat detection(s)", "protection", "bad")
    flags = (sm.get("ext_high") or 0) + (sm.get("startup") or 0) + (sm.get("tasks") or 0) + (sm.get("search") or 0)
    if flags:
        hit(min(15, 4 * flags), f"{flags} extension(s), startup item(s), task(s) or browser setting(s) to review", "protection")
    st = r.get("startup") or {}
    if (st.get("enabled") or 0) > 15:
        hit(5, f"{st['enabled']} items start automatically", "startup")
    h = r.get("health") or {}
    for d in h.get("disks") or []:
        if d.get("health") and d["health"] != "Healthy":
            hit(20, f"Disk {d['name']} reports {d['health']}", "dashboard", "bad")
    if h.get("reboot"):
        hit(5, "; ".join(h["reboot"]), "dashboard")
    b = h.get("battery") or {}
    if b.get("health") and b["health"] < 70:
        hit(5, f"Battery holds {b['health']}% of its design capacity", "dashboard")
    u = r.get("updates") or {}
    if (u.get("count") or 0) >= 5:
        hit(5, f"{u['count']} app updates available", "apps")
    return max(0, s), issues


# ---------------------------------------------------------------- recommendations: context -> provider -> allowlisted, validated actions
AI_DEFAULT = {"enabled": False, "provider": "rules", "base_url": "http://127.0.0.1:1234/v1", "model": "", "key_env": "OPENROUTER_API_KEY", "timeout": 45}
ACTIONS = {
    "clean": {"risk": "low", "reversible": False, "label": "Clean temp/cache files", "note": "Temp and cache files are deleted (not recycled); apps recreate them. Files in use are skipped."},
    "recycle": {"risk": "low", "reversible": True, "label": "Move files to the Recycle Bin", "note": "Restorable from the Recycle Bin."},
    "organize": {"risk": "medium", "reversible": True, "label": "Organize a folder", "note": "Undo (Ctrl+Z on the Organize tab) puts every file back."},
    "startup_disable": {"risk": "low", "reversible": True, "label": "Switch off a startup item", "note": "Switch it back on any time on the Startup tab; nothing is deleted."},
    "defender_quickscan": {"risk": "low", "reversible": True, "label": "Run a Defender Quick Scan", "note": "Read-only scan; changes nothing."},
    "winget_upgrade": {"risk": "high", "reversible": False, "label": "Upgrade an app with winget", "note": "Installs a newer version and accepts its license; can't be undone here."},
    "empty_bin": {"risk": "high", "reversible": False, "label": "Empty the Recycle Bin", "note": "Permanent: files can't be restored afterwards."},
    "review": {"risk": "none", "reversible": True, "label": "Review", "note": "Opens the right tab so you can decide; changes nothing."},
}
AI_FORBIDDEN = {"empty_bin", "recycle"}  # the AI never proposes permanent deletes or raw file lists
REVIEW_TABS = {"scan": ("", "map", "large", "dups", "old"), "cleanup": ("", "installers"), "organize": ("",), "apps": ("", "programs", "updates", "orphans", "store"),
               "protection": ("",), "startup": ("",), "monitor": ("",)}
PREVIEWS = {}
RECS = {"last": None}


def _ai_fields(s, b):
    if b.get("provider") in ("rules", "openai"):
        s["provider"] = b["provider"]
    if "base_url" in b:
        u = str(b["base_url"]).strip()
        if u and not re.fullmatch(r"https?://\S+", u):
            raise ValueError("Endpoint must start with http:// or https://")
        s["base_url"] = u
    if "model" in b:
        s["model"] = str(b["model"]).strip()[:120]
    if "key_env" in b:
        k = str(b["key_env"]).strip()
        if k and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", k):
            raise ValueError("Enter the NAME of an environment variable (like OPENROUTER_API_KEY), not the key itself")
        s["key_env"] = k
    if "timeout" in b:
        try:
            s["timeout"] = max(10, min(120, int(b["timeout"])))
        except (TypeError, ValueError):
            raise ValueError("Timeout must be a number of seconds")
    return s


def load_ai():
    d = load_json(AI_FILE, {})
    s = dict(AI_DEFAULT)
    if isinstance(d, dict):
        s.update({k: d[k] for k in AI_DEFAULT if k in d})
    s["enabled"] = s["enabled"] is True
    if s["provider"] not in ("rules", "openai"):
        s["provider"] = "rules"
    try:
        s["timeout"] = max(10, min(120, int(s.get("timeout") or 45)))
    except (TypeError, ValueError):
        s["timeout"] = 45
    return s


def save_ai(b):
    s = load_ai()
    if "enabled" in b:
        s["enabled"] = b["enabled"] is True
    _ai_fields(s, b)
    save_json(AI_FILE, s)
    RECS["last"] = None
    log_action("SETTINGS", f"Recommendations {'ON' if s['enabled'] else 'OFF'}, provider {s['provider']}" + (f", model {s['model']}" if s["provider"] == "openai" else ""))
    return ai_public(s)


def ai_public(s=None):
    s = s or load_ai()
    return {**s, "key_present": bool(s["key_env"] and os.environ.get(s["key_env"]))}


def _smart():
    return SMART["last"] or load_json(SMART_FILE, None) or {}


def _startup_list():
    hit = _cache.get("startup")
    if hit:
        return hit[1]
    return [dict(x, cmd="") for x in ((_smart().get("startup") or {}).get("notable") or [])]


def capabilities(sm=None):
    """What can actually run on this PC right now. Impossible actions are never offered or accepted."""
    sm = sm if sm is not None else _smart()
    p = sm.get("protection") or {}
    if PROT["last"]:
        p = {"defender_active": PROT["last"]["av"]["defender_active"], "managed_note": PROT["last"]["av"]["managed_note"]}
    c = CATS["last"] or sm.get("cleanup") or {}
    wl = WINGET["last"] or sm.get("updates") or {}
    fails = winget_failures()
    st = _startup_list()
    return {"admin": is_admin(), "defender_quickscan": bool(p.get("defender_active")),
            "defender_note": (p.get("managed_note") or "")[:200] if not p.get("defender_active") else "",
            "clean_ids": [x["id"] for x in c.get("cats") or [] if not x.get("review_only") and x.get("size") and not x.get("running")],
            "browsers_open": [x["name"] for x in c.get("cats") or [] if x.get("running")],
            "empty_bin": bool((c.get("recycle") or {}).get("size")), "scan_loaded": bool(SCAN["result"]),
            "winget": bool(winget_exe()), "winget_ids": [u["id"] for u in wl.get("items") or [] if u.get("applyable") and u["id"] not in fails],
            "startup_ids": [i["id"] for i in st if i.get("can_toggle") and i.get("enabled")]}


def _loose_downloads():
    try:
        return organize_plan(DOWNLOADS, "type", True)["total"]
    except Exception:
        return 0


def allowed_for_ai(caps):
    acts = []
    if caps["clean_ids"]:
        acts.append({"type": "clean", "ids": caps["clean_ids"]})
    if caps["startup_ids"]:
        acts.append({"type": "startup_disable", "id": caps["startup_ids"][:30]})
    if _loose_downloads() >= 10:
        acts.append({"type": "organize", "folder": DOWNLOADS, "rule": ["type", "date"]})
    if caps["winget_ids"]:
        acts.append({"type": "winget_upgrade", "id": caps["winget_ids"][:40]})
    if caps["defender_quickscan"]:
        acts.append({"type": "defender_quickscan"})
    acts.append({"type": "review", "tab": {k: [s for s in v if s] for k, v in REVIEW_TABS.items()}, "filter": "optional: a program, startup item or file name to highlight"})
    return acts


MB = lambda n: round((n or 0) / 2 ** 20)


def build_context():
    """Compact snapshot for the model: sizes, names, ages and ids only (never file contents, never secrets)."""
    sm = _smart()
    caps = capabilities(sm)
    c = CATS["last"] or sm.get("cleanup") or {}
    dl = sm.get("downloads") or {}
    ss = last_scan_summary() or sm.get("scan_summary") or {}
    st = sm.get("startup") or {}
    p = sm.get("protection") or {}
    ap = sm.get("apps") or {}
    wl = WINGET["last"] or sm.get("updates") or {}
    fails = winget_failures()
    stl = _startup_list()
    notable = [i for i in stl if i.get("enabled") and (i.get("broken") or i.get("suspicious") or i.get("impact") == "high")]
    on_av = [x["name"] for x in p.get("products") or [] if x.get("on") and "defender" not in str(x.get("name", "")).lower()]
    ctx = {
        "pc": {"admin": caps["admin"], "smart_scan_time": sm.get("time"), "health_score": sm.get("score"),
               "drives": [{"drive": d["root"], "free_gb": round(d["free"] / 2 ** 30, 1), "total_gb": round(d["total"] / 2 ** 30, 1)} for d in (sm.get("drives") or drives())]},
        "capabilities": {"defender_quickscan": caps["defender_quickscan"], "defender_unavailable_because": caps["defender_note"], "admin": caps["admin"],
                         "browsers_open": caps["browsers_open"], "scan_results_loaded": caps["scan_loaded"],
                         "permanent_deletes_allowed": False},
        "junk": [{"id": x["id"], "name": x["name"], "size": fmt(x["size"]), "mb": MB(x["size"]), "files": x.get("files", 0), "cleanable": x["id"] in caps["clean_ids"],
                  "opt_in": bool(x.get("optin")), "review_only": bool(x.get("review_only")), "browser_open": bool(x.get("running"))}
                 for x in c.get("cats") or [] if x.get("size")],
        "recycle_bin": {"items": (c.get("recycle") or {}).get("items", 0), "size": fmt((c.get("recycle") or {}).get("size") or 0), "mb": MB((c.get("recycle") or {}).get("size"))},
        "downloads": {"older_than_days": dl.get("days"), "old_files": dl.get("old_count"), "old_size": fmt(dl.get("old_size") or 0), "old_mb": MB(dl.get("old_size")),
                      "cloud_only_files_not_counted": dl.get("cloud_count"), "partial_count": dl.get("partial"),
                      "biggest_old_files": [{"name": x["name"], "mb": MB(x["size"]), "age_days": x["age_days"]} for x in dl.get("top_old") or []][:10],
                      "biggest_old_folders": [{"name": x["name"], "mb": MB(x["size"]), "files": x["files"]} for x in dl.get("top_folders") or []][:5],
                      "old_installers": {"count": (dl.get("installers") or {}).get("count"), "size": fmt((dl.get("installers") or {}).get("size") or 0), "mb": MB((dl.get("installers") or {}).get("size")),
                                         "top": [{"name": x["name"], "mb": MB(x["size"]), "age_days": x["age_days"]} for x in (dl.get("installers") or {}).get("top") or []][:6]}}
        if dl else None,
        "duplicates": {"sets": ss.get("dup_groups"), "extra_copies_size": fmt(ss.get("dup_waste") or 0), "extra_copies_mb": MB(ss.get("dup_waste")), "scan_time": ss.get("time"),
                       "top": [{"name": g["name"], "copies": g["copies"], "mb_each": MB(g["size"])} for g in ss.get("dup_top") or []][:8]} if ss else None,
        "startup": {"total": st.get("total"), "enabled": st.get("enabled"),
                    "notable": [{"id": i["id"], "name": i["name"], "kind": i.get("kind"), "impact": i.get("impact"), "signature": i.get("signature"),
                                 "broken": bool(i.get("broken")), "why_broken": i.get("broken_reason") or i.get("why") or "", "can_switch_off": bool(i.get("can_toggle"))}
                                for i in notable][:20]},
        "security": {"active_antivirus": on_av, "defender_active": bool(p.get("defender_active")),
                     "multiple_antivirus_registered": len(on_av) > 1,
                     "antivirus_programs_installed": [x["name"] for x in ap.get("av_programs") or []],
                     "flagged_extensions": [{"name": e["name"], "browser": e["browser"], "level": e["level"]} for e in p.get("extensions") or []][:8],
                     "threats": (p.get("summary") or {}).get("threats", 0)},
        "app_updates": {"count": len(wl.get("items") or []),
                        "items": [{"id": u["id"], "name": u["name"][:40], "from": u["version"], "to": u["available"],
                                   **({"last_upgrade_failed": fails[u["id"]]["title"]} if u["id"] in fails else {})} for u in (wl.get("items") or [])][:40]},
        "allowed_actions": allowed_for_ai(caps),
    }
    return ctx


def _item(title, reason, action, tab, size=0, impact="", sub="", filt=""):
    return {"title": title, "reason": reason, "action": action, "tab": tab, "size": size, "impact": impact, "sub": sub, "filter": filt}


def rules_recommend(ctx):
    """Deterministic local rules. Always specific: names, sizes and counts from the last Smart Scan / Scan."""
    out = []
    sm = _smart()
    caps = capabilities(sm)
    c = CATS["last"] or sm.get("cleanup") or {}
    for cat in c.get("cats") or []:
        sz = cat.get("size") or 0
        if cat.get("review_only"):
            if sz > 2 ** 30:
                out.append(_item(f"{cat['name']}: {fmt(sz)}", f"{cat.get('desc', '')} It needs admin, so this app only measures it.",
                                 {"type": "review", "tab": "cleanup", "filter": cat["name"]}, "cleanup", sz, f"up to {fmt(sz)}"))
            continue
        if sz < (500 if cat["id"] == "temp" else 150) * 2 ** 20:
            continue
        if cat.get("running"):
            out.append(_item(f"Close {cat['name'].split(' cache')[0]} to clear its {fmt(sz)} cache", "The browser is open, so its cache can't be cleaned right now.",
                             {"type": "review", "tab": "cleanup", "filter": cat["name"]}, "cleanup", sz, f"frees {fmt(sz)}"))
            continue
        why = {"temp": f"{cat.get('files', 0):,} files in your TEMP folder are more than a day old.",
               "logs": f"{cat.get('files', 0):,} log files older than 30 days.", "devcache": "Opt-in: the next npm/pip install re-downloads what it needs."}.get(
            cat["id"], (cat.get("desc") or "Cache files that rebuild themselves.").split(". ")[0].rstrip(".") + ".")
        nm = cat['name'] if cat['id'] in ('edge', 'chrome', 'firefox') else cat['name'][0].lower() + cat['name'][1:]
        out.append(_item(f"Clear {fmt(sz)} of {nm if cat['id'] != 'temp' else 'old temporary files'}", why,
                         {"type": "clean", "ids": [cat["id"]]}, "cleanup", sz, f"frees {fmt(sz)}"))
    rb = c.get("recycle") or (sm.get("cleanup") or {}).get("recycle") or {}
    if rb.get("size", 0) > 2 ** 30:
        out.append(_item(f"Empty the Recycle Bin ({fmt(rb['size'])}, {rb.get('items', 0):,} items)",
                         "Permanent. Check nothing in it is still needed first.", {"type": "empty_bin"}, "cleanup", rb["size"], f"frees {fmt(rb['size'])}"))
    r = SCAN["result"]
    ss = last_scan_summary() or {}
    if r and r["dups"]:
        paths, size = [], 0
        for g in r["dups"][:50]:
            for f in g["files"][1:]:
                if not f.get("protected") and key(f["path"]) in r["deletable"]:
                    paths.append(f["path"])
                    size += g["size"]
        if size > 100 * 2 ** 20:
            top = ", ".join(f"'{os.path.basename(g['files'][0]['path'])}' x{len(g['files'])}" for g in r["dups"][:3])
            out.append(_item(f"Recycle {len(paths)} extra duplicate copies ({fmt(size)})", f"The oldest copy of each set is kept. Biggest: {top}.",
                             {"type": "recycle", "paths": paths}, "scan", size, f"frees {fmt(size)}", "dups"))
    elif ss.get("dup_waste", 0) > 100 * 2 ** 20:
        top = ", ".join(f"'{g['name']}' x{g['copies']}" for g in (ss.get("dup_top") or [])[:3])
        out.append(_item(f"Review {fmt(ss['dup_waste'])} of duplicate copies ({ss.get('dup_groups', 0)} sets)",
                         f"From the scan on {ss.get('time', '?')}. Biggest: {top}. Run Scan again to pick copies to recycle.",
                         {"type": "review", "tab": "scan", "sub": "dups"}, "scan", ss["dup_waste"], f"up to {fmt(ss['dup_waste'])}", "dups"))
    dl = sm.get("downloads") or {}
    if dl.get("old_size", 0) > 2 ** 30:
        fold = "; ".join(f"'{x['name']}' {fmt(x['size'])}" for x in (dl.get("top_folders") or [])[:3])
        big = (dl.get("top_old") or [{}])[0]
        out.append(_item(f"Review {fmt(dl['old_size'])} of Downloads older than {dl['days']} days ({dl['old_count']:,} files)",
                         f"Biggest: {fold}." + (f" Largest file: '{big.get('name')}' {fmt(big.get('size', 0))}, {big.get('age_days')} days old." if big else ""),
                         {"type": "review", "tab": "scan", "sub": "old"}, "scan", dl["old_size"], f"up to {fmt(dl['old_size'])}", "old"))
    inst = dl.get("installers") or (c.get("installers") or {})
    if inst.get("count", 0) >= 3 and inst.get("size", 0) > 200 * 2 ** 20:
        names = ", ".join(f"'{x['name']}'" for x in (inst.get("top") or inst.get("items") or [])[:3] if x.get("name") or x.get("path"))
        out.append(_item(f"{inst['count']} old installers in Downloads ({fmt(inst['size'])})", f"Setup files older than 30 days, e.g. {names}. Keep any you still need.",
                         {"type": "review", "tab": "cleanup", "sub": "installers"}, "cleanup", inst["size"], f"up to {fmt(inst['size'])}", "installers"))
    loose = _loose_downloads()
    if loose >= 30:
        out.append(_item(f"Organize {loose} loose files in Downloads", "Sorted into type folders (Images, PDFs, Installers...). Preview first; one click undoes it.",
                         {"type": "organize", "folder": DOWNLOADS, "rule": "type"}, "organize", 0, f"tidies {loose} files"))
    for i in _startup_list():
        if not i.get("enabled"):
            continue
        why = i.get("broken_reason") or i.get("why") or ""
        if i.get("broken"):
            t = f"Switch off broken startup item '{i['name']}'"
            reason = f"{i.get('kind', 'Startup item')}: {why}, so it fails at every sign-in."
        elif i.get("suspicious"):
            t = f"Check unsigned startup item '{i['name']}'"
            reason = "An unsigned program from AppData/Temp starts at sign-in."
        else:
            continue
        if i.get("can_toggle"):
            out.append(_item(t, reason, {"type": "startup_disable", "id": i["id"]}, "startup", 0, "faster, cleaner sign-in", filt=i["name"]))
        else:
            out.append(_item(t.replace("Switch off", "Review"), reason + (" Needs admin to switch off." if i.get("needs_admin") else " This app can't switch this type off."),
                             {"type": "review", "tab": "startup", "filter": i["name"]}, "startup", 0, "", filt=i["name"]))
    p = sm.get("protection") or {}
    on_av = [x["name"] for x in p.get("products") or [] if x.get("on") and "defender" not in str(x.get("name", "")).lower()]
    if len(on_av) > 1:
        extra = [n for n in on_av if not re.search(r"sophos|crowdstrike|sentinel|carbon black|trend|eset|symantec endpoint", n, re.I)] or on_av[1:]
        progs = (sm.get("apps") or {}).get("av_programs") or []
        pn = progs[0]["name"] if progs else extra[0]
        out.append(_item(f"Remove leftover {extra[0]} alongside {[n for n in on_av if n not in extra][0] if len(extra) < len(on_av) else on_av[0]}",
                         f"{len(on_av)} antivirus products register as active ({', '.join(on_av)}). Two at once slow the PC; on a work PC keep the one IT manages.",
                         {"type": "review", "tab": "apps", "sub": "programs", "filter": pn.split()[0]}, "apps", 0, "faster, fewer conflicts", "programs", pn.split()[0]))
    for e in (p.get("extensions") or [])[:3]:
        if re.search(r"mcafee|webadvisor|norton|avast|avg", e.get("name") or "", re.I) or e.get("level") == "high":
            out.append(_item(f"Review the '{e['name']}' extension in {e['browser']}", "Security-suite browser add-ons often come bundled and read every page you visit.",
                             {"type": "review", "tab": "protection", "filter": e["name"]}, "protection", 0, "privacy", filt=e["name"]))
    if caps["defender_quickscan"]:
        out.append(_item("Run a Defender Quick Scan", "A quick check of the usual malware locations.", {"type": "defender_quickscan"}, "protection", 0, "read-only check"))
    wl = WINGET["last"] or sm.get("updates") or {}
    fails = winget_failures()
    ups = [u for u in wl.get("items") or [] if u.get("applyable")]
    for u in [u for u in ups if u["id"] not in fails][:4]:
        out.append(_item(f"Update {u['name']} ({u['version']} → {u['available']})", f"winget has a newer version ({u['id']}).",
                         {"type": "winget_upgrade", "id": u["id"]}, "apps", 0, "latest fixes", "updates"))
    for pid, fx in list(fails.items())[:3]:
        u = next((x for x in wl.get("items") or [] if x["id"] == pid), None)
        if u:
            out.append(_item(f"{u['name']} update failed last time ({fx.get('title', '')})", fx.get("message", ""),
                             {"type": "review", "tab": "apps", "sub": "updates", "filter": u["name"]}, "apps", 0, "", "updates", u["name"]))
    if len(ups) > 4:
        out.append(_item(f"{len(ups)} app updates are available", "Open Updates to pick the ones you want. Each asks you to confirm.",
                         {"type": "review", "tab": "apps", "sub": "updates"}, "apps", 0, "", "updates"))
    for iss in sm.get("issues") or []:
        if iss["sev"] == "bad":
            out.append(_item(iss["text"], "Needs your review.", {"type": "review", "tab": iss["tab"] if iss["tab"] in REVIEW_TABS else "protection"}, iss["tab"]))
    return out


def _http_post(url, body, headers, timeout=60):
    import urllib.request
    import socket
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json", **headers}, method="POST")
    end = time.time() + timeout  # hard deadline: OpenRouter keeps slow requests alive with whitespace, so a socket timeout alone never fires
    with urllib.request.urlopen(req, timeout=min(timeout, 20)) as r:
        buf = bytearray()
        while True:
            if time.time() > end:
                raise socket.timeout("timed out")
            chunk = r.read1(65536) if hasattr(r, "read1") else r.read(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8"))


def _http_get(url, headers, timeout=20):
    import urllib.request
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _redact(text, key=""):
    t = str(text or "")
    if key:
        t = t.replace(key, "[key]")
    return re.sub(r"(sk-[A-Za-z0-9_\-]{6,}|Bearer\s+\S+)", "[key]", t)


def _err_text(e, key="", timeout=45):
    import urllib.error, socket
    if isinstance(e, urllib.error.HTTPError):
        msg = ""
        try:
            body = json.loads(e.read().decode("utf-8", "replace") or "{}")
            msg = (body.get("error") or {}).get("message", "") if isinstance(body.get("error"), dict) else str(body.get("error") or "")
        except Exception:
            pass
        hint = {401: "the key was rejected", 402: "the account needs credits for this model", 404: "model or endpoint not found",
                429: "rate-limited (free models allow a limited number of requests per minute)"}.get(e.code, "")
        return _redact(f"HTTP {e.code}" + (f" ({hint})" if hint else "") + (f": {msg[:160]}" if msg else ""), key)
    if isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in str(e).lower():
        return f"No answer within {timeout} s"
    if isinstance(e, urllib.error.URLError):
        return _redact(f"Can't reach the endpoint: {e.reason}", key)
    return _redact(f"{type(e).__name__}: {str(e)[:160]}", key)


SYS_PROMPT = (
    "You are the recommendations engine inside a local Windows cleanup app. You receive a JSON snapshot of THIS PC. "
    "Return ONLY a JSON object: {\"items\": [...]} with 4 to 8 items, most impactful first (biggest space savings, then broken or risky startup items "
    "and security, then updates). Each item: {\"title\": string (max 80 chars; name the specific thing and include its size or count from the snapshot), "
    "\"reason\": string (max 200 chars; cite names and numbers from the snapshot), \"impact\": string (max 40 chars, like \"frees 11.9 GB\"), "
    "\"action\": object}. The action MUST match one entry of allowed_actions, using only the parameter values listed there: "
    "{\"type\":\"clean\",\"ids\":[...]}, {\"type\":\"startup_disable\",\"id\":\"...\"}, {\"type\":\"organize\",\"folder\":\"...\",\"rule\":\"type\"}, "
    "{\"type\":\"winget_upgrade\",\"id\":\"...\"}, {\"type\":\"defender_quickscan\"} (only if listed), or "
    "{\"type\":\"review\",\"tab\":\"scan|cleanup|apps|protection|startup|organize\",\"sub\":\"...\",\"filter\":\"name to highlight\"} for anything that needs the "
    "user's judgment (old downloads, duplicates, installers, leftover antivirus, browser extensions, items that need admin). "
    "Rules: never invent ids, names, paths or numbers; never suggest permanent deletion or emptying the Recycle Bin; never suggest an action that is not in "
    "allowed_actions or that capabilities say is unavailable; no generic advice such as 'review startup programs' or 'clean temp files' without the specific "
    "name and size; skip anything under 100 MB unless it is security-related or a broken startup entry; don't upgrade apps whose last upgrade failed; when quoting a size, copy the snapshot's \"size\" text exactly "
    "(it uses 1 GB = 1024 MB) instead of converting mb yourself; one item per thing, no repeats.")


def _parse_items(txt):
    t = (txt or "").strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.S)
    cands = [t]
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        cands.append(m.group(1))
    for pat in (r"\[.*\]", r"\{.*\}"):
        m = re.search(pat, t, re.S)
        if m:
            cands.append(m.group(0))
    for cand in cands:
        try:
            v = json.loads(cand)
        except ValueError:
            continue
        if isinstance(v, dict):
            v = v.get("items") or v.get("recommendations")
        if isinstance(v, list):
            return v
    return []


class RulesProvider:
    """Deterministic local rules. No network."""
    name = "rules"

    def recommend(self, ctx):
        return rules_recommend(ctx)


class OpenAICompatProvider:
    """Any OpenAI-compatible /chat/completions endpoint (LM Studio, Ollama, OpenRouter). Used only when Recommendations are ON and
    this provider is picked. The key is read from the named environment variable at call time; it is never stored or logged.
    The model may only pick from the capability-filtered allowlist; every action is re-validated server-side before it can even be shown."""
    name = "openai"

    def __init__(self, cfg):
        self.cfg = cfg
        self.meta = {}

    def recommend(self, ctx):
        import urllib.error
        if not self.cfg.get("enabled") or not self.cfg.get("base_url") or not self.cfg.get("model"):
            return []
        key = os.environ.get(self.cfg.get("key_env") or "", "")
        body = {"model": self.cfg["model"], "temperature": 0.1, "max_tokens": 8000,
                "messages": [{"role": "system", "content": SYS_PROMPT}, {"role": "user", "content": json.dumps(ctx, default=str, separators=(",", ":"))[:20000]}],
                "response_format": {"type": "json_object"}}
        url = self.cfg["base_url"].rstrip("/") + "/chat/completions"
        hdr = {"Authorization": f"Bearer {key}"} if key else {}
        if "openrouter.ai" in url:
            hdr.update({"HTTP-Referer": "http://127.0.0.1/pc-cleanup", "X-Title": "PC Cleanup"})
            # free router often lands on "thinking" models that can spend the whole budget reasoning: keep it short
            body["reasoning"] = {"effort": "low", "exclude": True}
        t0 = time.time()
        tmo = self.cfg.get("timeout", 45)
        try:
            r = _http_post(url, body, hdr, timeout=self.cfg.get("timeout", 45))
            self.meta["json_mode"] = True
        except urllib.error.HTTPError as e:
            if e.code not in (400, 404, 415, 422):
                raise
            body.pop("response_format")  # endpoint/model doesn't support JSON mode: ask again without it
            body.pop("reasoning", None)
            r = _http_post(url, body, hdr, timeout=max(10, tmo - (time.time() - t0)))
            self.meta["json_mode"] = False
        ch = (r.get("choices") or [{}])[0]
        msg = ch.get("message") or {}
        if not (msg.get("content") or "").strip() and ch.get("finish_reason") == "length" and tmo - (time.time() - t0) > 15:
            # spent the whole budget thinking: one retry with the least reasoning the model allows
            body["messages"][0]["content"] = SYS_PROMPT + "\nAnswer with the JSON object immediately. Keep any thinking very short."
            for eff in (("none", "minimal") if "reasoning" in body else (None,)):
                if eff:
                    body["reasoning"] = {"effort": eff, "exclude": True}  # "none" turns thinking off where the model allows it
                try:
                    r = _http_post(url, body, hdr, timeout=max(10, tmo - (time.time() - t0)))
                    ch = (r.get("choices") or [{}])[0]; msg = ch.get("message") or {}
                    self.meta["retried"] = True
                    break
                except Exception:
                    if tmo - (time.time() - t0) < 12:
                        break
        self.meta.update(seconds=round(time.time() - t0, 1), model=str(r.get("model") or self.cfg["model"])[:80], finish=ch.get("finish_reason"))
        content = msg.get("content") or ""
        items = _parse_items(content)
        if not items and not content.strip() and msg.get("reasoning"):
            items = _parse_items(str(msg["reasoning"])[-6000:])  # some models put the final JSON in the reasoning field
        self.meta["empty"] = not content.strip()
        return [{"title": str(it["title"])[:120], "reason": str(it.get("reason", ""))[:300], "impact": str(it.get("impact", ""))[:60],
                 "action": it.get("action") if isinstance(it.get("action"), dict) else None, "tab": ""}
                for it in items if isinstance(it, dict) and it.get("title")]


def review_size(a):
    sm = _smart()
    if a.get("tab") == "scan" and a.get("sub") == "dups":
        return (last_scan_summary() or {}).get("dup_waste", 0)
    if a.get("tab") == "scan" and a.get("sub") == "old":
        return (sm.get("downloads") or {}).get("old_size", 0)
    if a.get("tab") == "cleanup":
        c = CATS["last"] or sm.get("cleanup") or {}
        if a.get("sub") == "installers":
            return ((sm.get("downloads") or {}).get("installers") or c.get("installers") or {}).get("size", 0)
        f = (a.get("filter") or "").lower()
        for x in c.get("cats") or []:
            if f and (f == x["name"].lower() or f == x["id"]):
                return x.get("size", 0)
    return 0


def _sig(it):
    a = it["action"] or {}
    t = a.get("type")
    if t == "clean":
        return {"clean:" + i for i in a["ids"]}
    if t == "startup_disable":
        return {"st:" + a["id"], "name:" + (it.get("filter") or "").lower()} - {"name:"}
    if t == "winget_upgrade":
        return {"wg:" + a["id"]}
    if t == "organize":
        return {"org:" + norm(a["folder"])}
    if t == "recycle":
        return {"dups"}
    if t == "empty_bin":
        return {"bin"}
    if t == "defender_quickscan":
        return {"qs"}
    if t == "review":
        if a["tab"] == "scan" and a.get("sub") in ("dups", "old"):
            return {"dups" if a["sub"] == "dups" else "olddl"}
        if a["tab"] == "cleanup" and a.get("sub") == "installers":
            return {"inst"}
        if a["tab"] == "apps" and a.get("sub") == "updates" and not a.get("filter"):
            return {"updates"}
        k = {f"rv:{a['tab']}:{a.get('sub', '')}:{(a.get('filter') or '').lower()}"}
        if a.get("filter"):
            k.add("name:" + a["filter"].lower())
        return k
    return {json.dumps(a, sort_keys=True)}


def _specific(text):
    return bool(re.search(r"\d", text or "")) or bool(re.search(r"'[^']{2,}'|\"[^\"]{2,}\"", text or ""))


def _finalize(r, src, allowed_types):
    a = r.get("action")
    if not isinstance(a, dict):
        if src == "AI":
            return None  # generic advice with no action: dropped
        a = {"type": "review", "tab": r.get("tab") if r.get("tab") in REVIEW_TABS else "protection"}
    if src == "AI" and (a.get("type") in AI_FORBIDDEN or a.get("type") not in allowed_types):
        return None
    try:
        na, desc = validate_action(a)
    except Exception:
        return None  # never show an action that fails validation
    title, reason = str(r.get("title", ""))[:120], str(r.get("reason", ""))[:300]
    if src == "AI" and na["type"] in ("review", "clean", "organize") and not _specific(title + " " + reason):
        return None  # too generic
    spec = ACTIONS[na["type"]]
    size = desc.get("size") or r.get("size") or 0
    impact = r.get("impact") or ""
    if src == "AI" and size:  # trust the app's own numbers over the model's
        impact = (f"up to {fmt(size)}" if na["type"] == "review" else f"frees {fmt(size)}")
    elif src == "AI" and na["type"] in ("organize", "startup_disable", "winget_upgrade"):
        # these free no space: don't let the model claim gigabytes
        impact = {"organize": "tidier folders, undoable", "startup_disable": "cleaner sign-in, undoable", "winget_upgrade": "newer version"}[na["type"]]
        if na["type"] == "organize":
            title = re.sub(r"\s*\([^)]*\d\s*[KMGT]?B\b[^)]*\)", "", title).strip() or title
    if na["type"] == "review" and na.get("filter") and not r.get("filter"):
        r["filter"] = na["filter"]
    return {"title": title, "reason": reason, "impact": impact[:60], "action": na, "risk": spec["risk"], "reversible": spec["reversible"],
            "permanent": na["type"] in ("clean", "empty_bin"), "size": size, "tab": na.get("tab") if na["type"] == "review" else (r.get("tab") or ""),
            "sub": na.get("sub", "") if na["type"] == "review" else (r.get("sub") or ""), "filter": na.get("filter") or r.get("filter") or "", "source": src}


def _rank(it):
    t = it["action"]["type"]
    if it["size"] >= 100 * 2 ** 20:
        return (0, -it["size"])
    if t == "startup_disable" or (t == "review" and it["tab"] in ("startup", "protection")) or "antivirus" in it["reason"]:
        return (1, 0)
    if t == "winget_upgrade" or (t == "review" and it["tab"] == "apps"):
        return (2, 0)
    return (3, -it["size"])


def recommendations(refresh=False):
    cfg = load_ai()
    if not cfg["enabled"]:
        return {"enabled": False, "provider": cfg["provider"], "items": []}  # OFF: nothing computed, no network
    if RECS["last"] and not refresh:
        return RECS["last"]
    ctx = build_context()
    allowed = {a["type"] for a in ctx["allowed_actions"]}
    note, meta, ai_raw = "", {}, []
    if cfg["provider"] == "openai":
        prov = OpenAICompatProvider(cfg)
        try:
            ai_raw = prov.recommend(ctx)
            if not ai_raw:
                note = ("The AI model used its whole answer budget thinking and returned no text"
                        if prov.meta.get("empty") and prov.meta.get("finish") == "length" else
                        "The AI answered but gave nothing usable") + f" ({prov.meta.get('model') or cfg['model']}); showing the built-in rules. Try Refresh again or pick another model."
        except Exception as e:
            note = f"AI didn't work this time ({_err_text(e, os.environ.get(cfg.get('key_env') or '', ''), cfg['timeout'])}); showing the built-in rules instead."
        meta = prov.meta
    rules = RulesProvider().recommend(ctx)
    items, seen, dropped = [], set(), 0
    for src, lst in (("AI", ai_raw), ("rules", rules)):
        for r in lst:
            it = _finalize(r, src, allowed)
            if not it:
                dropped += src == "AI"
                continue
            k = _sig(it)
            if k & seen:
                continue
            seen |= k
            items.append(it)
    items.sort(key=_rank)
    items = items[:18]
    for n, it in enumerate(items):
        it["n"] = n
    n_ai = sum(1 for i in items if i["source"] == "AI")
    if cfg["provider"] == "openai" and ai_raw and not n_ai and not note:
        note = "The AI's suggestions were too generic or not allowed on this PC; showing the built-in rules."
    RECS["last"] = {"enabled": True, "provider": cfg["provider"], "items": items, "note": note, "time": time.strftime("%H:%M"),
                    "ai_count": n_ai, "ai_dropped": dropped, "model": meta.get("model", ""), "seconds": meta.get("seconds"),
                    "json_mode": meta.get("json_mode"), "has_smart": bool(_smart())}
    if cfg["provider"] == "openai":
        log_action("AI", f"Recommendations refresh: {n_ai} AI + {len(items) - n_ai} rules item(s), {dropped} AI item(s) dropped"
                         + (f", model {meta.get('model')}, {meta.get('seconds')}s" if meta.get("model") else "") + (f"; {note}" if note else ""))
    return RECS["last"]


def ai_test(b):
    """User-initiated: one tiny request to check the endpoint, model and key. Reports latency and errors, never the key."""
    cfg = _ai_fields(load_ai(), {k: b[k] for k in ("base_url", "model", "key_env", "timeout") if k in b})
    if not cfg["base_url"] or not cfg["model"]:
        raise ValueError("Enter an endpoint and a model first")
    key = os.environ.get(cfg["key_env"] or "", "")
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    hdr = {"Authorization": f"Bearer {key}"} if key else {}
    t0 = time.time()
    out = {"key_present": bool(key), "endpoint": re.sub(r"^(https?://[^/]+).*$", r"\1", cfg["base_url"]), "requested_model": cfg["model"], "timeout": cfg["timeout"]}
    try:
        r = _http_post(url, {"model": cfg["model"], "temperature": 0, "max_tokens": 300,
                             "messages": [{"role": "user", "content": "Reply with exactly this JSON and nothing else: {\"ok\": true}"}]}, hdr, timeout=cfg["timeout"])
        msg = ((r.get("choices") or [{}])[0].get("message") or {})
        out.update(ok=True, ms=int((time.time() - t0) * 1000), model=str(r.get("model") or cfg["model"])[:80],
                   provider=str(r.get("provider") or "")[:40], reply=_redact(str(msg.get("content") or "")[:80], key))
    except Exception as e:
        out.update(ok=False, ms=int((time.time() - t0) * 1000), error=_err_text(e, key, cfg["timeout"]))
    log_action("AI", f"Tested AI connection to {out['endpoint']} ({cfg['model']}): " + (f"OK in {out['ms']} ms, model {out.get('model')}" if out["ok"] else f"failed: {out['error']}"))
    return out


def ai_models(b):
    """User-initiated: list the endpoint's models (OpenRouter: free ones first)."""
    cfg = _ai_fields(load_ai(), {k: b[k] for k in ("base_url", "key_env") if k in b})
    if not cfg["base_url"]:
        raise ValueError("Enter an endpoint first")
    key = os.environ.get(cfg["key_env"] or "", "")
    try:
        r = _http_get(cfg["base_url"].rstrip("/") + "/models", {"Authorization": f"Bearer {key}"} if key else {}, timeout=20)
    except Exception as e:
        raise ValueError("Couldn't list models: " + _err_text(e, key, 20))
    data = r.get("data") if isinstance(r, dict) else r
    ids = []
    for m in data or []:
        if isinstance(m, dict) and m.get("id"):
            pr = m.get("pricing") or {}
            free = str(m["id"]).endswith(":free") or (str(pr.get("prompt")) in ("0", "0.0") and str(pr.get("completion")) in ("0", "0.0"))
            ids.append({"id": str(m["id"])[:120], "free": free})
    ids.sort(key=lambda x: (not x["free"], x["id"]))
    if "openrouter.ai" in cfg["base_url"] and not any(x["id"] == "openrouter/free" for x in ids):
        ids.insert(0, {"id": "openrouter/free", "free": True})
    return {"items": ids[:300]}


def validate_action(a):
    """Only allowlisted action types with validated parameters. Returns (normalized_action, description)."""
    if not isinstance(a, dict) or a.get("type") not in ACTIONS:
        raise ValueError("Unknown action")
    t = a["type"]
    spec = ACTIONS[t]
    desc = {"label": spec["label"], "note": spec["note"], "reversible": spec["reversible"], "risk": spec["risk"], "targets": [], "size": 0}
    if t == "clean":
        ok_ids = clean_ids()
        ids = [i for i in a.get("ids") or [] if i in ok_ids]
        if not ids:
            raise ValueError("No cleanup category")
        cats = {c["id"]: c for c in (CATS["last"] or (_smart().get("cleanup") or {})).get("cats", [])}
        if any(cats.get(i, {}).get("running") for i in ids):
            raise ValueError("Close the browser first; its cache can't be cleaned while it's open")
        desc["targets"] = [f"{cats.get(i, {}).get('name', i)} — {fmt(cats.get(i, {}).get('size', 0))}, {cats.get(i, {}).get('files', 0):,} files"
                           + (f" ({', '.join(cats.get(i, {}).get('roots', [])[:2])})" if cats.get(i, {}).get("roots") else "") for i in ids]
        desc["size"] = sum(cats.get(i, {}).get("size", 0) for i in ids)
        return {"type": t, "ids": ids}, desc
    if t == "recycle":
        r = SCAN["result"]
        paths = [p for p in a.get("paths") or [] if isinstance(p, str)][:2000]
        if not r or not paths or any(key(p) not in r["deletable"] or not user_path_ok(p) for p in paths):
            raise ValueError("Those files aren't in the last scan's results")
        desc["targets"] = paths
        desc["size"] = sum(os.path.getsize(p) for p in paths if os.path.isfile(p))
        return {"type": t, "paths": paths}, desc
    if t == "organize":
        rule = a.get("rule") if a.get("rule") in ("type", "date") else "type"
        plan = organize_plan(a.get("folder", ""), rule, True)
        if not plan["total"]:
            raise ValueError("Nothing to organize")
        desc["targets"] = [f"{plan['total']} files in {plan['folder']} → " + ", ".join(f"{g} ({n})" for g, n in plan["groups"][:8])]
        desc["size"] = 0
        desc["moves"] = sum(i["size"] for i in plan["items"])
        return {"type": t, "folder": plan["folder"], "rule": rule}, desc
    if t == "startup_disable":
        it = next((i for i in (cached("startup", 300, startup_items) if IS_WIN else (_cache.get("startup") or (0, []))[1]) if i["id"] == a.get("id")), None)
        if not it or not it["can_toggle"] or not it["enabled"]:
            raise ValueError("That startup item can't be switched off")
        desc["targets"] = [f"{it['name']} ({it.get('kind', '')}): {it['cmd']}" + (f" — {it['broken_reason']}" if it.get("broken_reason") else "")]
        return {"type": t, "id": it["id"]}, desc
    if t == "defender_quickscan":
        caps = capabilities()
        if not caps["defender_quickscan"]:
            raise ValueError(caps["defender_note"] or "Microsoft Defender isn't the active antivirus on this PC, so a Defender scan can't run.")
        desc["targets"] = ["Microsoft Defender Quick Scan"]
        return {"type": t}, desc
    if t == "winget_upgrade":
        u = next((x for x in (WINGET["last"] or {}).get("items", []) if x["id"] == a.get("id") and x["applyable"]), None)
        if not u:
            raise ValueError("That app isn't in the last update check")
        desc["targets"] = [f"{u['name']} {u['version']} → {u['available']} ({u['id']})"]
        fx = winget_failures().get(u["id"])
        if fx:
            desc["note"] += f" Last attempt failed: {fx.get('title')} ({fx.get('hex')}). {fx.get('message', '')}"
        return {"type": t, "id": u["id"]}, desc
    if t == "review":
        tab = a.get("tab") if a.get("tab") in REVIEW_TABS else None
        if not tab:
            raise ValueError("Unknown tab")
        sub = a.get("sub") if a.get("sub") in REVIEW_TABS[tab] else ""
        filt = re.sub(r"[^\w .,'()+\-&]", "", str(a.get("filter") or ""))[:60].strip()
        na = {"type": t, "tab": tab, **({"sub": sub} if sub else {}), **({"filter": filt} if filt else {})}
        desc["targets"] = [f"Opens {tab}" + (f" › {sub}" if sub else "") + (f", highlighting '{filt}'" if filt else "")]
        desc["size"] = review_size(na)
        return na, desc
    info = recycle_bin_info()  # empty_bin
    desc["targets"] = [f"{info['items']} item(s) in the Recycle Bin"]
    desc["size"] = info["size"]
    return {"type": t}, desc


def action_preview(actions):
    out = []
    for a in actions:
        na, desc = validate_action(a)
        if na["type"] == "review":
            continue  # navigation only, nothing to confirm or apply
        tok = uuid.uuid4().hex
        PREVIEWS[tok] = (na, time.time())
        out.append({"token": tok, "action": na, **desc})
    for k in [k for k, v in PREVIEWS.items() if time.time() - v[1] > 300]:
        PREVIEWS.pop(k, None)
    if not out:
        raise ValueError("Nothing to apply")
    return {"items": out}


def action_apply(token, confirm):
    if confirm != "yes":
        raise ValueError("Not confirmed")
    ent = PREVIEWS.pop(token, None)
    if not ent or time.time() - ent[1] > 300:
        raise ValueError("This confirmation expired. Press Apply again.")
    a, _ = validate_action(ent[0])  # re-check against the current state
    t = a["type"]
    log_action("APPLY", f"Confirmed recommendation: {ACTIONS[t]['label']} " + json.dumps({k: v for k, v in a.items() if k != "paths"}) +
               (f" ({len(a['paths'])} files)" if t == "recycle" else ""))
    RECS["last"] = None
    if t == "clean":
        return {"job": start_job("clean", clean_job, a["ids"], False).view(False)}
    if t == "recycle":
        return {"result": recycle_files(a["paths"]), "undo": "recycle"}
    if t == "organize":
        plan = organize_plan(a["folder"], a["rule"], True)
        return {"result": organize_apply(a["folder"], a["rule"], True, [i["name"] for i in plan["items"]]), "undo": "organize"}
    if t == "startup_disable":
        return {"result": startup_set(a["id"], False), "undo": "startup", "id": a["id"]}
    if t == "defender_quickscan":
        return {"job": start_job("quickscan", quickscan_job).view(False)}
    if t == "winget_upgrade":
        return {"job": start_job("upgrade", winget_upgrade_job, a["id"]).view(False)}
    info = recycle_bin_info()
    ok = empty_recycle_bin()
    log_action("EMPTY BIN", f"Emptied the Recycle Bin: {info['items']} item(s), {fmt(info['size'])} ({'ok' if ok else 'failed'})")
    return {"result": {"ok": ok, "freed": info["size"] if ok else 0, "items": info["items"]}}


# ---------------------------------------------------------------- saved organize rules
def save_rule(b):
    name = str(b.get("name", "")).strip()[:60]
    if not name:
        raise ValueError("Give the rule a name")
    folder = validate_folder(b.get("folder", ""))
    s = load_settings()
    rules = [r for r in s.get("saved_rules") or [] if r["name"] != name]
    rules.append({"name": name, "folder": folder, "rule": b.get("rule") if b.get("rule") in ("type", "date") else "type", "skip_links": bool(b.get("skip_links", True))})
    s["saved_rules"] = rules[-20:]
    save_json(SETTINGS_FILE, s)
    return s["saved_rules"]


def delete_rule(name):
    s = load_settings()
    s["saved_rules"] = [r for r in s.get("saved_rules") or [] if r["name"] != name]
    save_json(SETTINGS_FILE, s)
    return s["saved_rules"]


def open_location(path):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError("bad path")
    if not IS_WIN:
        return {"ok": True}
    if os.path.isfile(path):
        subprocess.Popen(["explorer.exe", "/select,", path])
    elif os.path.isdir(path):
        subprocess.Popen(["explorer.exe", path])
    elif os.path.isdir(os.path.dirname(path)):
        subprocess.Popen(["explorer.exe", os.path.dirname(path)])
    else:
        raise ValueError("That location doesn't exist")
    return {"ok": True}


SETTINGS_PAGES = {"storage": "ms-settings:storagesense", "apps": "ms-settings:appsfeatures", "startup": "ms-settings:startupapps",
                  "security": "windowsdefender:"}


def open_settings(page):
    """Opens a fixed Windows Settings page (navigation only)."""
    uri = SETTINGS_PAGES.get(page)
    if not uri:
        raise ValueError("Unknown settings page")
    if IS_WIN:
        os.startfile(uri)
    return {"ok": True}


def ext_get(p, q):
    f = q.get("force") == "1"
    if p == "/api/apps":
        return programs_payload(f)
    if p == "/api/apps/store":
        return {"items": cached("store", 300, store_apps, f)}
    if p == "/api/startup":
        return startup_payload(f)
    if p == "/api/protection":
        return PROT["last"] or {}
    if p == "/api/mon":
        return MON.payload()
    if p == "/api/procs":
        MON.touch()
        return {"items": list_processes(), "ncpu": os.cpu_count()}
    if p == "/api/health":
        return health_info(f)
    if p == "/api/winget":
        return {**(WINGET["last"] or {}), "failures": winget_failures()}
    if p == "/api/space":
        sm = _smart()
        return space_summary(CATS["last"] or sm.get("cleanup"), sm.get("downloads"), last_scan_summary() or sm.get("scan_summary"))
    if p == "/api/caps":
        return capabilities()
    if p == "/api/smart":
        return SMART["last"] or load_json(SMART_FILE, {}) or {}
    if p == "/api/reg/backups":
        return {"items": reg_backups(), "dir": REG_BACKUP_DIR}
    if p == "/api/ai":
        return ai_public()
    if p == "/api/recs":
        return recommendations(False)
    if p == "/api/rules":
        return {"items": load_settings().get("saved_rules") or []}
    return None


def _need(b):
    if b.get("confirm") != "yes":
        raise ValueError("Not confirmed")


def ext_post(p, b):
    if p == "/api/apps/leftovers":
        prog = find_program(b.get("id", ""))
        if not prog:
            raise ValueError("Program not found")
        r = leftovers_result(prog, find_leftovers(prog, still_installed=True), "Read-only preview while the program is still installed.")
        log_action("DRY RUN", f"Leftover preview for {prog['name']}: {len(r['items'])} item(s), {fmt(r['size'])}")
        return r
    if p == "/api/apps/uninstall":
        _need(b)
        prog = find_program(b.get("id", ""))
        if not prog:
            raise ValueError("Program not found")
        return start_job("uninstall", uninstall_job, prog, bool(b.get("quiet"))).view(False)
    if p == "/api/apps/remove-leftovers":
        _need(b)
        return remove_leftovers(b.get("token", ""), b.get("items") or [])
    if p == "/api/apps/orphans":
        return start_job("orphans", orphan_scan).view(False)
    if p == "/api/reg/restore":
        _need(b)
        return reg_restore(b.get("file", ""))
    if p == "/api/protection/scan":
        return start_job("protection", protection_job).view(False)
    if p == "/api/protection/quickscan":
        _need(b)
        return start_job("quickscan", quickscan_job).view(False)
    if p == "/api/startup/toggle":
        _need(b)
        return startup_set(b.get("id", ""), b.get("enable") is True)
    if p == "/api/proc/end":
        _need(b)
        return end_process(b.get("pid"), b.get("name", ""), b.get("created", ""))
    if p == "/api/winget/check":
        return start_job("winget", winget_job).view(False)
    if p == "/api/winget/upgrade":
        _need(b)
        a, _ = validate_action({"type": "winget_upgrade", "id": b.get("id")})
        return start_job("upgrade", winget_upgrade_job, a["id"]).view(False)
    if p == "/api/smart/start":
        return start_job("smart", smart_job).view(False)
    if p == "/api/admin/relaunch":
        return relaunch_admin()
    if p == "/api/open":
        return open_location(b.get("path", ""))
    if p == "/api/open/settings":
        return open_settings(b.get("page", ""))
    if p == "/api/ai/test":
        return ai_test(b)
    if p == "/api/ai/models":
        return ai_models(b)
    if p == "/api/ai/settings":
        return save_ai(b)
    if p == "/api/recs/refresh":
        return recommendations(True)
    if p == "/api/recs/preview":
        acts = b.get("actions")
        if not isinstance(acts, list) or not acts:
            raise ValueError("Nothing to apply")
        return action_preview(acts[:20])
    if p == "/api/recs/apply":
        return action_apply(b.get("token", ""), b.get("confirm"))
    if p == "/api/rules/save":
        return {"items": save_rule(b)}
    if p == "/api/rules/delete":
        return {"items": delete_rule(str(b.get("name", "")))}
    return None


HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>PC Cleanup &amp; Organizer</title>
<link rel="icon" href="/favicon.ico">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{
  --bg:#0d1017; --panel:#141822; --panel2:#1a1f2c; --line:#262c3b; --text:#e8ebf2; --muted:#8a93a8;
  --accent:#7c6cff; --accent2:#2dd4bf; --danger:#ff5d73; --warn:#ffa94d; --info:#6ea8fe; --ok:#3ddc97; --r:14px;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font-family:"Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;font-size:14px}
button,input,select{font:inherit;color:inherit}
.app{display:grid;grid-template-columns:248px 1fr;height:100vh}
.side{background:linear-gradient(180deg,#121621,#0f121b);border-right:1px solid var(--line);display:flex;flex-direction:column;padding:20px 14px;min-height:0}
.brand{display:flex;align-items:center;gap:11px;padding:4px 8px 22px}
.logo{width:36px;height:36px;border-radius:11px;background:linear-gradient(135deg,var(--accent2),var(--accent));display:grid;place-items:center;box-shadow:0 6px 18px #2dd4bf40}
.logo svg{width:21px;height:21px}
.brand b{display:block;font-size:15px;letter-spacing:.2px} .brand small{color:var(--muted);font-size:12px}
.sect{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1.3px;padding:10px 10px 6px}
.nav{display:flex;align-items:center;gap:11px;width:100%;background:none;border:0;border-radius:10px;padding:9px 10px;cursor:pointer;color:#c4cad8;text-align:left;margin-bottom:2px;transition:background .15s}
.nav:hover{background:#ffffff08}
.nav.on{background:linear-gradient(90deg,#2dd4bf22,#2dd4bf08);color:#fff;box-shadow:inset 3px 0 0 var(--accent2)}
.nav svg{width:18px;height:18px;flex:none;color:var(--accent2)} .nav span{flex:1}
.nav .badge{font-size:11px;background:#ffffff10;color:var(--muted);border-radius:20px;padding:1px 8px}
kbd{font-family:inherit;font-size:11px;background:#ffffff0d;border:1px solid #ffffff1a;border-bottom-width:2px;border-radius:6px;padding:0 6px;color:var(--muted);line-height:17px;display:inline-block;min-width:18px;text-align:center}
.sdrives{margin-top:auto;padding:8px 4px 4px}
.sdrive{padding:8px 8px 10px;font-size:12px;color:var(--muted)}
.sdrive .t{display:flex;justify-content:space-between;margin-bottom:6px} .sdrive .t b{color:var(--text);font-weight:600}
.mbar{height:6px;border-radius:6px;background:#ffffff0d;overflow:hidden} .mbar i{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,var(--accent2),var(--accent))}
.mbar i.hot{background:linear-gradient(90deg,var(--warn),var(--danger))}
.sbtn{display:flex;align-items:center;gap:10px;width:100%;background:none;border:1px solid var(--line);border-radius:10px;padding:8px 10px;cursor:pointer;color:#c4cad8;margin-top:8px}
.sbtn:hover{border-color:#3a4257;background:#ffffff05} .sbtn svg{width:16px;height:16px;color:var(--muted)} .sbtn span{flex:1;text-align:left}
.main{overflow:auto;padding:26px 32px 90px;min-width:0}
.view{display:none;max-width:1100px;margin:0 auto} .view.on{display:block;animation:viewin .22s ease}
@keyframes viewin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.vh{display:flex;align-items:flex-end;gap:14px;margin-bottom:18px}
.vh h1{margin:0;font-size:25px;letter-spacing:-.3px} .vh p{margin:4px 0 0;color:var(--muted)} .vh .sp{flex:1}
.card{background:linear-gradient(180deg,var(--panel),#121620);border:1px solid var(--line);border-radius:var(--r);padding:16px 18px;margin-bottom:14px}
.btn{background:linear-gradient(135deg,var(--accent),#9a7bff);border:0;border-radius:10px;padding:9px 16px;cursor:pointer;font-weight:600;color:#fff;box-shadow:0 4px 14px #7c6cff44;white-space:nowrap;display:inline-flex;align-items:center;gap:8px}
.btn:hover{filter:brightness(1.08)} .btn:disabled{opacity:.45;cursor:not-allowed;filter:none}
.btn kbd{background:#ffffff22;border-color:#ffffff33;color:#fff}
.btn.teal{background:linear-gradient(135deg,#14b8a6,#2dd4bf);box-shadow:0 4px 14px #2dd4bf33;color:#04201c} .btn.teal kbd{color:#04201c;background:#ffffff44}
.btn.danger{background:linear-gradient(135deg,#ff5d73,#ff8a5b);box-shadow:0 4px 14px #ff5d7340}
.ghost{background:#ffffff08;border:1px solid var(--line);border-radius:10px;padding:8px 13px;cursor:pointer;color:#cfd5e2;display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
.ghost:hover{background:#ffffff10;border-color:#3a4257} .ghost svg{width:15px;height:15px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.pathbox{flex:1;min-width:260px;display:flex;align-items:center;gap:9px;background:#0d1017;border:1px solid var(--line);border-radius:10px;padding:0 12px}
.pathbox:focus-within{border-color:var(--accent)} .pathbox svg{width:17px;height:17px;color:var(--muted);flex:none}
.pathbox input{flex:1;background:none;border:0;outline:none;padding:10px 0;min-width:0}
.chips{display:flex;gap:7px;flex-wrap:wrap;margin-top:11px}
.chip{background:#ffffff08;border:1px solid var(--line);color:#c4cad8;border-radius:20px;padding:4px 12px;cursor:pointer;font-size:12.5px;display:inline-flex;align-items:center;gap:6px}
.chip:hover{border-color:#3a4257} .chip.on{border-color:var(--accent2);background:#2dd4bf1a;color:#fff}
.chip b{font-weight:600;color:var(--accent2)}
.drives{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;margin-bottom:14px}
.drive{display:flex;gap:14px;align-items:center;padding:14px 16px;margin:0}
.ring{width:58px;height:58px;flex:none;position:relative}
.ring svg{width:58px;height:58px;transform:rotate(-90deg)} .ring b{position:absolute;inset:0;display:grid;place-items:center;font-size:12.5px}
.drive .dt b{display:block;font-size:15px} .drive .dt small{color:var(--muted);font-size:12.5px;display:block;margin-top:2px}
.prog{margin-top:14px} .prog[hidden]{display:none}
.bar{height:8px;border-radius:8px;background:#ffffff0d;overflow:hidden;position:relative}
.bar i{position:absolute;top:0;bottom:0;left:0;border-radius:8px;background:linear-gradient(90deg,var(--accent2),var(--accent));transition:width .3s}
.bar.indet i{width:35%!important;animation:indet 1.2s ease-in-out infinite}
@keyframes indet{from{left:-35%}to{left:100%}}
.ptext{display:flex;align-items:center;gap:12px;margin-top:9px;color:var(--muted);font-size:12.5px}
.ptext span{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px}
.stat{padding:14px 16px;margin:0} .stat small{color:var(--muted);font-size:12px;display:block} .stat b{display:block;font-size:22px;margin-top:4px;letter-spacing:-.3px}
.stat em{font-style:normal;font-size:12px;color:var(--muted)}
.subtabs{display:flex;gap:4px;background:#0f131c;border:1px solid var(--line);border-radius:12px;padding:4px;margin-bottom:14px;width:max-content}
.subtab{background:none;border:0;border-radius:9px;padding:7px 14px;cursor:pointer;color:var(--muted);display:inline-flex;gap:7px;align-items:center}
.subtab.on{background:#ffffff10;color:#fff} .subtab .n{font-size:11px;background:#ffffff10;border-radius:20px;padding:0 7px}
.crumbs{display:flex;flex-wrap:wrap;gap:4px;align-items:center;margin-bottom:12px;font-size:13px}
.crumbs button{background:none;border:0;color:var(--accent2);cursor:pointer;padding:2px 4px;border-radius:6px} .crumbs button:hover{background:#2dd4bf14}
.crumbs button:last-child{color:#fff;font-weight:600} .crumbs i{color:#3a4257;font-style:normal}
.strip{display:flex;height:54px;border-radius:12px;overflow:hidden;margin-bottom:14px;gap:2px;background:#0d1017}
.seg{min-width:3px;cursor:pointer;position:relative;display:flex;align-items:flex-end;padding:6px 8px;font-size:11.5px;color:#fff;overflow:hidden;white-space:nowrap;text-shadow:0 1px 3px #0008;transition:filter .15s}
.seg:hover{filter:brightness(1.2)}
.dlist .drow{display:grid;grid-template-columns:22px minmax(160px,1.3fr) 2fr 96px 92px;gap:12px;align-items:center;padding:9px 10px;border-radius:10px;cursor:pointer}
.dlist .drow:hover{background:#ffffff06} .drow .sw{width:12px;height:12px;border-radius:4px}
.drow .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap} .drow .sz{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.drow .ct{text-align:right;color:var(--muted);font-size:12px}
.drow .mbar{height:8px}
.tag{font-size:11px;border-radius:20px;padding:1px 8px;margin-left:6px;background:#6ea8fe1f;color:var(--info);white-space:nowrap}
.tag.warn{background:#ffa94d1f;color:var(--warn)} .tag.bad{background:#ff5d731f;color:var(--danger)} .tag.ok{background:#3ddc971f;color:var(--ok)}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:8px 10px;border-bottom:1px solid #ffffff08;vertical-align:middle}
tr.pick{cursor:pointer} tr.pick:hover td{background:#ffffff05} tr.sel td{background:#7c6cff14}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.fname{font-weight:500;word-break:break-all} .fdir{color:var(--muted);font-size:12px;word-break:break-all;margin-top:2px}
.cb{width:18px;height:18px;border-radius:6px;border:2px solid #3a4257;display:grid;place-items:center;flex:none;transition:.12s}
.cb svg{width:12px;height:12px;opacity:0} .on>.cb,.sel .cb,.cb.on{background:var(--accent);border-color:var(--accent)} .on>.cb svg,.sel .cb svg,.cb.on svg{opacity:1}
.cb.off{opacity:.3}
.group{padding:0;overflow:hidden} .group .gh{display:flex;gap:12px;align-items:center;padding:12px 16px;background:#ffffff04;border-bottom:1px solid var(--line)}
.group .gh b{flex:1} .group .gh small{color:var(--muted)}
.empty{text-align:center;padding:50px 20px;color:var(--muted)}
.empty .big{width:74px;height:74px;border-radius:22px;margin:0 auto 16px;display:grid;place-items:center;background:linear-gradient(135deg,var(--accent2),var(--accent));box-shadow:0 14px 34px #2dd4bf30;animation:float 3.2s ease-in-out infinite}
.empty .big svg{width:38px;height:38px} .empty h3{color:var(--text);margin:0 0 6px;font-size:17px}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.selbar{position:fixed;left:calc(248px + 50%);transform:translateX(calc(-50% - 124px));bottom:20px;background:#1d2334;border:1px solid #2f3851;border-radius:14px;padding:9px 9px 9px 18px;display:flex;align-items:center;gap:14px;box-shadow:0 18px 50px #000a;z-index:30;animation:zoom .18s ease}
.selbar[hidden]{display:none} .selbar b{color:#fff}
.cgrid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:14px}
.cat{display:flex;gap:14px;align-items:flex-start;cursor:pointer;margin:0;transition:border-color .15s,transform .15s}
.cat:hover{border-color:#3a4257} .cat.on{border-color:#7c6cff88;box-shadow:0 0 0 1px #7c6cff44 inset}
.cat.dis{cursor:default;opacity:.75}
.cat .ic{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;flex:none} .cat .ic svg{width:22px;height:22px}
.cat .ct{flex:1;min-width:0} .cat .ct b{display:block;font-size:15px} .cat .ct small{color:var(--muted);font-size:12.5px;line-height:1.45;display:block;margin-top:3px}
.cat .cs{text-align:right} .cat .cs b{display:block;font-size:19px;font-variant-numeric:tabular-nums} .cat .cs small{color:var(--muted);font-size:12px}
.cat .cb{margin-top:3px}
.sumbar{display:flex;align-items:center;gap:16px}
.sumbar .tot{flex:1} .sumbar .tot small{color:var(--muted);display:block;font-size:12px} .sumbar .tot b{font-size:22px}
.toggle{display:inline-flex;align-items:center;gap:9px;cursor:pointer;user-select:none;color:#cfd5e2;background:none;border:0;padding:4px}
.toggle .sw{width:36px;height:20px;border-radius:20px;background:#2a3142;position:relative;transition:.2s;flex:none}
.toggle .sw::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:.2s}
.toggle.on .sw{background:var(--accent2)} .toggle.on .sw::after{left:18px}
.rbin{display:flex;align-items:center;gap:16px}
.rbin .ic{width:46px;height:46px;border-radius:13px;display:grid;place-items:center;background:#ff5d731a;color:var(--danger)} .rbin .ic svg{width:24px;height:24px}
.rbin .rt{flex:1} .rbin .rt small{display:block;color:var(--muted);font-size:12.5px;margin-top:2px}
.result{border-color:#3ddc9755;background:linear-gradient(180deg,#3ddc970d,#121620)}
.result.dry{border-color:#6ea8fe55;background:linear-gradient(180deg,#6ea8fe0d,#121620)}
.result h3{margin:0 0 8px;font-size:15px;display:flex;gap:8px;align-items:center}
.result ul{margin:6px 0 0;padding-left:18px;color:#cfd5e2;line-height:1.7}
.seg2{display:inline-flex;background:#0f131c;border:1px solid var(--line);border-radius:10px;padding:3px}
.seg2 button{background:none;border:0;padding:6px 12px;border-radius:8px;cursor:pointer;color:var(--muted)} .seg2 button.on{background:#ffffff12;color:#fff}
.optrow{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-top:14px}
.undo{display:flex;align-items:center;gap:14px;border-color:#ffa94d44;background:linear-gradient(180deg,#ffa94d0b,#121620)}
.undo .ic{color:var(--warn)} .undo .ic svg{width:22px;height:22px} .undo .ut{flex:1} .undo small{color:var(--muted);display:block;font-size:12.5px}
.gchips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.gchip{display:flex;align-items:center;gap:8px;background:#ffffff06;border:1px solid var(--line);border-radius:12px;padding:7px 12px}
.gchip svg{width:16px;height:16px;color:var(--accent2)} .gchip b{font-variant-numeric:tabular-nums}
.arrow{color:#3a4257;padding:0 4px} .dest{color:var(--accent2);word-break:break-all}
details{margin-top:12px;color:var(--muted)} summary{cursor:pointer;font-size:13px} details ul{margin:8px 0 0;padding-left:18px;line-height:1.7;font-size:12.5px}
.applybar{display:flex;align-items:center;gap:14px;margin-top:14px} .applybar .sp{flex:1;color:var(--muted);font-size:12.5px}
.log{padding:6px 0} .lrow{display:grid;grid-template-columns:150px 96px 1fr;gap:12px;padding:9px 18px;border-bottom:1px solid #ffffff07;font-size:13px;align-items:baseline}
.lrow time{color:var(--muted);font-variant-numeric:tabular-nums;font-size:12.5px} .lrow .m{word-break:break-word;color:#d5dae6}
.kind{font-size:11px;font-weight:600;letter-spacing:.4px;border-radius:20px;padding:2px 9px;text-align:center;background:#ffffff0d;color:var(--muted);justify-self:start}
.k-SCAN{background:#6ea8fe1f;color:var(--info)} .k-CLEAN,.k-RECYCLE{background:#3ddc971f;color:var(--ok)} .k-ORGANIZE{background:#7c6cff26;color:#b3a9ff}
.k-UNDO{background:#ffa94d1f;color:var(--warn)} .k-DRY{background:#2dd4bf1a;color:var(--accent2)} .k-EMPTY,.k-ERROR{background:#ff5d731f;color:var(--danger)}
.modal-back{position:fixed;inset:0;background:#05070bb8;backdrop-filter:blur(5px);display:grid;place-items:center;z-index:50;animation:fadein .15s ease}
.modal-back[hidden]{display:none}
.modal{background:linear-gradient(180deg,#171c28,#131722);border:1px solid var(--line);border-radius:18px;width:min(560px,92vw);max-height:86vh;overflow:auto;padding:22px 26px 22px;box-shadow:0 30px 90px #000c;animation:zoom .2s cubic-bezier(.2,.9,.3,1.2)}
.modal.wide{width:min(800px,92vw)}
.modal .mh{display:flex;align-items:center;gap:12px;margin-bottom:14px} .modal .mh h2{margin:0;font-size:18px;flex:1}
.modal .mi{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;flex:none} .modal .mi svg{width:20px;height:20px}
.mi.danger{background:#ff5d731f;color:var(--danger)} .mi.move{background:#7c6cff26;color:#b3a9ff} .mi.k{background:linear-gradient(135deg,var(--accent2),var(--accent));color:#fff}
.mbody{color:#cfd5e2;line-height:1.55} .mbody ul{padding-left:18px;margin:8px 0;color:var(--muted);font-size:12.5px;word-break:break-all}
.mbody .big{font-size:26px;font-weight:700;color:#fff;margin:6px 0}
.mtype{margin-top:12px} .mtype input{width:100%;background:#0d1017;border:1px solid var(--line);border-radius:10px;padding:10px 12px;outline:none;letter-spacing:2px}
.mtype input:focus{border-color:var(--danger)}
.mfoot{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}
@keyframes fadein{from{opacity:0}to{opacity:1}} @keyframes zoom{from{opacity:0;transform:scale(.96) translateY(8px)}to{opacity:1;transform:none}}
.kgrid{display:grid;grid-template-columns:1fr 1fr;gap:4px 34px}
.ksec{color:var(--accent2);font-size:11px;text-transform:uppercase;letter-spacing:1.2px;margin:12px 0 4px}
.krow{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:6px 0;border-bottom:1px solid #ffffff08;font-size:13px;color:#cfd5e2}
.krow .keys{display:flex;gap:4px;align-items:center;flex:none;color:var(--muted);font-size:11px}
.knote{margin-top:16px;color:var(--muted);font-size:12.5px}
.snack{position:fixed;left:50%;bottom:22px;transform:translate(-50%,24px);opacity:0;pointer-events:none;transition:.25s cubic-bezier(.2,.9,.3,1.1);background:#20263a;border:1px solid #2f3851;border-radius:12px;padding:10px 16px;box-shadow:0 14px 40px #0009;z-index:60;font-size:13.5px;max-width:70vw}
.snack.show{opacity:1;transform:translate(-50%,0)} .snack.err{border-color:#ff5d7366}
.safe{display:flex;gap:10px;align-items:center;color:var(--muted);font-size:12.5px;margin-top:-6px;margin-bottom:16px}
.safe svg{width:15px;height:15px;color:var(--ok);flex:none}
.more{color:var(--muted);font-size:12.5px;padding:10px}
.num-in{width:70px;background:#0d1017;border:1px solid var(--line);border-radius:8px;padding:6px 8px;outline:none;text-align:center}
::-webkit-scrollbar{width:10px;height:10px} ::-webkit-scrollbar-thumb{background:#262c3b;border-radius:10px;border:2px solid var(--bg)}
.nav{padding:7px 10px}
.sect{padding:8px 10px 4px}
.adm{font-size:10.5px;border-radius:20px;padding:1px 7px;margin-left:4px;background:#ffa94d22;color:var(--warn);vertical-align:middle}
.adm:empty{display:none}
.adm.on{background:#3ddc971f;color:var(--ok)}
.dgrid{display:grid;grid-template-columns:330px 1fr;gap:14px;margin-bottom:14px}
.score{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;margin:0}
.score .big{position:relative;width:150px;height:150px} .score svg{width:150px;height:150px;transform:rotate(-90deg)}
.score .big b{position:absolute;inset:0;display:grid;place-items:center;font-size:40px;letter-spacing:-1px}
.score .big b small{display:block;font-size:12px;color:var(--muted);letter-spacing:0;font-weight:500;margin-top:-34px}
.score h3{margin:10px 0 2px} .score p{margin:0;color:var(--muted);font-size:12.5px}
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.tile{margin:0;cursor:pointer;transition:border-color .15s;padding:14px 16px;min-width:0} .tile:hover{border-color:#3a4257}
.tile .th{display:flex;align-items:center;gap:9px;color:var(--muted);font-size:12.5px} .tile .th svg{width:17px;height:17px;color:var(--accent2)}
.tile b{display:block;font-size:20px;margin-top:6px;letter-spacing:-.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis} .tile em{font-style:normal;color:var(--muted);font-size:12px;display:block;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.issues{margin:0;padding:0;list-style:none} .issues li{display:flex;gap:10px;align-items:center;padding:8px 2px;border-bottom:1px solid #ffffff08;font-size:13px;cursor:pointer}
.issues li:hover{color:#fff} .dot{width:8px;height:8px;border-radius:50%;flex:none;background:var(--warn)} .dot.bad{background:var(--danger)} .dot.ok{background:var(--ok)}
.rec{display:grid;grid-template-columns:1fr auto;gap:6px 14px;padding:12px 4px;border-bottom:1px solid #ffffff08;align-items:center}
.rec:last-child{border-bottom:0} .rec .rt b{font-weight:600} .rec .rt small{display:block;color:var(--muted);font-size:12.5px;margin-top:2px}
.rec .ra{display:flex;gap:8px;align-items:center}
.off{display:flex;align-items:center;gap:16px} .off .ic{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;background:#7c6cff1f;color:#b3a9ff;flex:none} .off .ic svg{width:22px;height:22px}
.off .t{flex:1} .off small{display:block;color:var(--muted);font-size:12.5px;margin-top:2px}
.search{min-width:220px;flex:0 1 320px}
select.sel{background:#0d1017;border:1px solid var(--line);border-radius:10px;padding:8px 10px;outline:none}
.tbl td small{color:var(--muted);font-size:12px;display:block;margin-top:2px;word-break:break-all}
.tbl td.act{white-space:nowrap;text-align:right}
.mini{padding:5px 10px;font-size:12.5px;border-radius:8px}
.lft{border-color:#7c6cff55;background:linear-gradient(180deg,#7c6cff0d,#121620)}
.mgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:14px}
.mcard{margin:0;min-width:0} .mcard .mh2{display:flex;justify-content:space-between;align-items:baseline;color:var(--muted);font-size:12.5px}
.mcard .val{font-size:24px;font-weight:700;color:#fff;letter-spacing:-.3px;margin:4px 0 2px;font-variant-numeric:tabular-nums}
.mcard .sub{color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.spark{width:100%;height:54px;display:block;margin-top:8px}
.cores{display:grid;grid-template-columns:repeat(10,1fr);gap:3px;margin-top:8px} .cores i{display:block;height:22px;border-radius:3px;background:#ffffff0a;position:relative;overflow:hidden}
.cores i span{position:absolute;left:0;right:0;bottom:0;background:linear-gradient(0deg,var(--accent),var(--accent2))}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:12.5px;margin-top:8px} .kv span{color:var(--muted)} .kv b{font-weight:500;text-align:right;font-variant-numeric:tabular-nums}
.tgl{display:inline-flex;align-items:center;background:none;border:0;cursor:pointer;padding:0}
.tgl .sw{width:34px;height:19px;border-radius:20px;background:#2a3142;position:relative;transition:.2s;flex:none}
.tgl .sw::after{content:"";position:absolute;top:2px;left:2px;width:15px;height:15px;border-radius:50%;background:#fff;transition:.2s}
.tgl.on .sw{background:var(--accent2)} .tgl.on .sw::after{left:17px} .tgl:disabled{opacity:.35;cursor:not-allowed}
.form{display:grid;grid-template-columns:170px 1fr;gap:12px 16px;align-items:center;margin-top:12px}
.form label{color:var(--muted);font-size:13px} .form input{background:#0d1017;border:1px solid var(--line);border-radius:10px;padding:9px 12px;outline:none;width:100%}
.form input:focus{border-color:var(--accent)}
.note{color:var(--muted);font-size:12.5px;line-height:1.55}
.snack button{margin-left:12px;background:#ffffff14;border:1px solid #ffffff22;border-radius:8px;padding:3px 10px;cursor:pointer;color:#fff}
.k-REGISTRY,.k-STARTUP,.k-APPLY,.k-UNINSTALL{background:#7c6cff26;color:#b3a9ff} .k-RESTORE,.k-PROTECT,.k-SETTINGS,.k-ADMIN,.k-UPDATE{background:#6ea8fe1f;color:var(--info)} .k-END{background:#ff5d731f;color:var(--danger)}
.rules{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px}
.rchip{display:inline-flex;align-items:center;gap:6px;background:#ffffff08;border:1px solid var(--line);border-radius:20px;padding:3px 4px 3px 12px;font-size:12.5px}
.rchip button{background:none;border:0;cursor:pointer;color:var(--muted);padding:2px 6px;border-radius:12px} .rchip button:hover{background:#ffffff10;color:#fff}
.rules input{background:#0d1017;border:1px solid var(--line);border-radius:10px;padding:6px 10px;outline:none;width:170px}
.cfm li{margin-bottom:4px}
/* v3 */
.sbig{display:flex;gap:28px;flex-wrap:wrap;margin:8px 0 10px} .sbig small{display:block;color:var(--muted);font-size:12px} .sbig b{font-size:22px;letter-spacing:-.3px;font-variant-numeric:tabular-nums}
.sprow{display:grid;grid-template-columns:1fr 160px 84px;gap:12px;align-items:center;padding:8px 2px;border-bottom:1px solid #ffffff08;cursor:pointer;font-size:13px}
.sprow:last-child{border-bottom:0} .sprow:hover{color:#fff} .sprow .mbar{height:6px} .sprow b{text-align:right;font-variant-numeric:tabular-nums}
.chipsz{font-size:11.5px;font-weight:700;color:#fff;background:linear-gradient(90deg,#2dd4bf40,#7c6cff40);border-radius:20px;padding:1px 9px;margin-left:6px;white-space:nowrap}
.tag.src-ai{background:#7c6cff2e;color:#c9c1ff} .tag.src-rules{background:#ffffff10;color:#cfd5e2}
.flash{animation:flash 1.1s ease 3} @keyframes flash{0%,100%{box-shadow:none}50%{box-shadow:0 0 0 2px #7c6cffaa inset;background:#7c6cff1a}}
.resrow{margin:6px 0 0;padding-left:18px;line-height:1.7} .resrow ul{margin:2px 0 4px;padding-left:16px}
.aitest{margin-top:10px;font-size:12.8px}
</style></head>
<body>
<div class="app">
<aside class="side">
  <div class="brand">
    <div class="logo"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 3l-7.5 7.5"/><path d="M9.5 9.5l5 5-1.8 6.2c-3.5-.6-7.6-3.4-9.7-7.3L9.5 9.5z"/><path d="M6.5 15.5l2-2M9 18.2l2-2"/></svg></div>
    <div><b>PC Cleanup</b><small>Clean &middot; Protect &middot; Monitor &middot; v3<span class="adm" id="admBadge"></span></small></div>
  </div>
  <div class="sect">Overview</div>
  <button class="nav" data-view="dashboard"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="2"/><rect x="14" y="3" width="7" height="5" rx="2"/><rect x="14" y="12" width="7" height="9" rx="2"/><rect x="3" y="16" width="7" height="5" rx="2"/></svg><span>Dashboard</span><kbd>1</kbd></button>
  <div class="sect">Clean</div>
  <button class="nav" data-view="scan"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-9-9"/><path d="M21 3v6h-6"/><path d="M12 7v5l3 2"/></svg><span>Scan &amp; disk map</span><kbd>2</kbd></button>
  <button class="nav" data-view="cleanup"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.8 4.6L18.5 9l-4.7 1.6L12 15l-1.8-4.4L5.5 9l4.7-1.4z"/><path d="M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z"/></svg><span>Cleanup</span><kbd>3</kbd></button>
  <button class="nav" data-view="organize"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M8 13h8M8 16h5"/></svg><span>Organize</span><kbd>4</kbd></button>
  <div class="sect">Care</div>
  <button class="nav" data-view="apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><path d="M14 17.5h7M17.5 14v7"/></svg><span>Applications</span><kbd>5</kbd></button>
  <button class="nav" data-view="protection"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/><path d="M12 8v4M12 16h.01"/></svg><span>Protection</span><kbd>6</kbd></button>
  <button class="nav" data-view="startup"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/></svg><span>Startup</span><kbd>7</kbd></button>
  <button class="nav" data-view="monitor"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg><span>Monitor</span><kbd>8</kbd></button>
  <button class="nav" data-view="activity"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg><span>Activity &amp; safety</span><kbd>9</kbd></button>
  <div class="sdrives" id="sdrives"></div>
  <button class="sbtn" id="setBtn" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg><span>Settings &amp; AI</span><kbd>,</kbd></button>
  <button class="sbtn" id="kbBtn" type="button"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="2.5" y="6" width="19" height="12" rx="2.5"/><path d="M6.5 10h.01M10 10h.01M13.5 10h.01M17 10h.01M7.5 14h9"/></svg><span>Keyboard shortcuts</span><kbd>?</kbd></button>
</aside>
<main class="main" id="main">

<section class="view" id="v-dashboard">
  <div class="vh"><div><h1>Dashboard</h1><p>One Smart Scan checks junk, protection, startup, apps, updates and hardware health. It only reads; it never changes anything.</p></div><div class="sp"></div>
    <button class="btn teal" id="smartBtn">Smart Scan <kbd>Ctrl R</kbd></button></div>
  <div class="card prog" id="smartProg" hidden><div class="bar" id="smartBar"><i style="width:0"></i></div><div class="ptext"><span id="smartText">Starting…</span><button class="ghost" id="smartCancel">Cancel <kbd>Esc</kbd></button></div></div>
  <div id="dashEmpty" class="empty card" hidden><div class="big"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/><path d="M9 12l2 2 4-4"/></svg></div>
    <h3>Run a Smart Scan to see your PC's health</h3><div>About a minute. Read-only: junk, antivirus and adware checks, startup items, installed apps, app updates, disks, battery and Windows Update.</div></div>
  <div id="dashRes" hidden>
    <div class="dgrid"><div class="card score" id="dashScore"></div><div class="tiles" id="dashTiles"></div></div>
    <div class="card" id="spaceCard" hidden></div>
    <div class="card" id="dashIssues"></div>
  </div>
  <div id="recResult"></div>
  <div class="card" id="recCard"></div>
</section>

<section class="view" id="v-scan">
  <div class="vh"><div><h1>Scan &amp; disk map</h1><p>See what's using your space. Scanning only reads; it never changes a file.</p></div></div>
  <div class="drives" id="drives"></div>
  <div class="card">
    <div class="row">
      <div class="pathbox"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg><input id="scanPath" spellcheck="false" placeholder="Folder to scan"></div>
      <button class="btn teal" id="scanBtn">Scan <kbd>Ctrl R</kbd></button>
    </div>
    <div class="chips" id="scanChips"></div>
    <div class="prog" id="scanProg" hidden>
      <div class="bar indet" id="scanBar"><i></i></div>
      <div class="ptext"><span id="scanPText">Starting…</span><button class="ghost" id="scanCancel">Cancel <kbd>Esc</kbd></button></div>
    </div>
  </div>
  <div id="scanEmpty" class="empty card"><div class="big"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg></div>
    <h3>Scan a folder to see where your space went</h3><div>You'll get a disk map, your 100 largest files, duplicate files and old downloads.</div></div>
  <div id="scanRes" hidden>
    <div class="stats" id="scanStats"></div>
    <div class="subtabs" id="subtabs"></div>
    <div class="card" id="st-map"></div>
    <div id="st-large"></div>
    <div id="st-dups"></div>
    <div id="st-old"></div>
  </div>
</section>

<section class="view" id="v-cleanup">
  <div class="vh"><div><h1>Cleanup</h1><p>Sizes are measured first. Nothing is removed until you confirm.</p></div><div class="sp"></div>
    <button class="ghost" id="measureBtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>Recalculate <kbd>Ctrl R</kbd></button></div>
  <div class="safe"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/><path d="M9 12l2 2 4-4"/></svg>Only temp, cache, crash-report and old log files. Cookies, history, passwords, browser profiles and system folders are never touched. Files in use are skipped and listed. OneDrive cloud-only files are never counted or downloaded.</div>
  <div class="cgrid" id="cats"></div>
  <div class="card sumbar">
    <div class="tot"><small>Selected to clean</small><b id="catTotal">–</b></div>
    <button class="toggle on" id="dryToggle" type="button"><span class="sw"></span>Dry run (preview only)</button>
    <button class="btn" id="cleanBtn">Run dry run</button>
  </div>
  <div id="cleanResult"></div>
  <div class="card rbin">
    <div class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/><path d="M10 10v6M14 10v6"/></svg></div>
    <div class="rt"><b>Recycle Bin</b><small id="rbText">Measuring…</small></div>
    <button class="btn danger" id="emptyBtn">Empty Recycle Bin…</button>
  </div>
  <div id="instCard"></div>
  <div id="catReview"></div>
</section>

<section class="view" id="v-organize">
  <div class="vh"><div><h1>Organize</h1><p>Sort the loose files in a folder into subfolders. You always see a preview first, and one click undoes it.</p></div></div>
  <div class="card">
    <div class="row">
      <div class="pathbox"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg><input id="orgPath" spellcheck="false" placeholder="Folder to organize"></div>
      <button class="btn teal" id="previewBtn">Preview <kbd>Ctrl R</kbd></button>
    </div>
    <div class="chips" id="orgChips"></div>
    <div class="optrow">
      <div class="seg2" id="ruleSeg"><button data-rule="type">By type</button><button data-rule="date">By date (YYYY\MM)</button></div>
      <button class="toggle on" id="linkToggle" type="button"><span class="sw"></span>Skip shortcuts (.lnk, .url)</button>
    </div>
    <div class="rules" id="orgRules"></div>
  </div>
  <div id="undoCard"></div>
  <div id="orgOut"></div>
</section>

<section class="view" id="v-apps">
  <div class="vh"><div><h1>Applications</h1><p>Uninstall programs together with their leftovers, check for updates, and find orphaned folders. Nothing is removed until you confirm.</p></div><div class="sp"></div><span id="appsAdmin"></span></div>
  <div class="subtabs" id="appTabs"></div>
  <div id="appLeft"></div>
  <div id="appBody"></div>
</section>

<section class="view" id="v-protection">
  <div class="vh"><div><h1>Protection</h1><p>Antivirus status plus read-only adware and privacy checks. Nothing is removed automatically.</p></div><div class="sp"></div>
    <button class="btn teal" id="protBtn">Run checks <kbd>Ctrl R</kbd></button></div>
  <div class="card prog" id="protProg" hidden><div class="bar indet"><i></i></div><div class="ptext"><span id="protText">Starting…</span></div></div>
  <div id="protBody"></div>
</section>

<section class="view" id="v-startup">
  <div class="vh"><div><h1>Startup</h1><p>Everything that starts when you sign in or when Windows boots. Switching an item off is reversible; nothing is deleted.</p></div><div class="sp"></div>
    <span id="stAdmin"></span><button class="ghost" id="stRefresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>Refresh <kbd>Ctrl R</kbd></button></div>
  <div id="stBody"><div class="card empty">Reading startup items…</div></div>
</section>

<section class="view" id="v-monitor">
  <div class="vh"><div><h1>Monitor</h1><p>Live CPU, memory, disk, network and GPU. Updates every second while this tab is open.</p></div><div class="sp"></div><span id="monUp" style="color:var(--muted);font-size:12.5px"></span></div>
  <div class="mgrid" id="monGrid"></div>
  <div class="card" style="padding:12px 14px">
    <div class="row" style="margin-bottom:8px"><b style="flex:1">Processes</b>
      <div class="pathbox search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg><input id="procQ" placeholder="Filter processes" spellcheck="false"></div>
      <div class="seg2" id="procSort"><button data-s="cpu">CPU</button><button data-s="mem">Memory</button><button data-s="name">Name</button></div></div>
    <div id="procList"></div>
  </div>
</section>

<section class="view" id="v-settings">
  <div class="vh"><div><h1>Settings</h1><p>Recommendations and AI. Off by default; nothing runs on its own.</p></div></div>
  <div class="card">
    <div class="row"><div style="flex:1"><b>Recommendations</b><div class="note">When on, the Dashboard lists suggestions. Each one has an Apply button that always shows a confirm card first. Off means nothing is computed and no network calls are made.</div></div>
      <button class="toggle" id="aiToggle" type="button"><span class="sw"></span><span id="aiState">Off</span></button></div>
    <div class="form">
      <label>Provider</label><div class="seg2" id="aiProv"><button data-p="rules">Built-in rules (local)</button><button data-p="openai">OpenAI-compatible AI</button></div>
      <label>Endpoint (base URL)</label><input id="aiUrl" spellcheck="false" placeholder="http://127.0.0.1:1234/v1">
      <label>Model</label><div class="row" style="gap:8px"><input id="aiModel" list="aiModelList" spellcheck="false" placeholder="openrouter/free" style="flex:1"><button class="ghost mini" id="aiLoadModels" type="button" title="Ask the endpoint which models it has">Load models</button></div>
      <label>API key variable</label><input id="aiKey" spellcheck="false" placeholder="OPENROUTER_API_KEY">
      <label>Timeout (seconds)</label><input id="aiTimeout" type="number" min="10" max="120" style="max-width:120px">
    </div>
    <datalist id="aiModelList"><option value="openrouter/free">OpenRouter picks a free model</option></datalist>
    <div class="aitest" id="aiTestOut"></div>
    <div class="note" style="margin-top:12px" id="aiNote"></div>
    <div class="applybar"><span class="sp">Examples: LM Studio http://127.0.0.1:1234/v1 · Ollama http://127.0.0.1:11434/v1 · OpenRouter https://openrouter.ai/api/v1</span><button class="ghost" id="aiTest">Test AI connection</button><button class="btn" id="aiSave">Save settings</button></div>
  </div>
</section>

<section class="view" id="v-activity">
  <div class="vh"><div><h1>Activity &amp; safety</h1><p>Every scan, preview, cleanup, move and undo is written to the activity log.</p></div><div class="sp"></div>
    <button class="ghost" id="logRefresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>Refresh</button></div>
  <div class="card"><b>Safety rules</b>
    <ul style="margin:8px 0 0;padding-left:18px;line-height:1.75;color:#cfd5e2">
      <li>Scans are read-only. OneDrive cloud-only files are never downloaded or hashed.</li>
      <li>Nothing is deleted or moved until you confirm it. Previews and dry runs are the default.</li>
      <li>Your own files go to the <b>Recycle Bin</b>, so you can restore them. Only temp and cache files are deleted directly.</li>
      <li>Windows, Program Files, ProgramData, AppData (outside the listed caches), app folders like .vscode, .git or node_modules, the folder this app is installed in and system files are blocked by the app itself.</li>
      <li>Organize moves only top-level files, renames on name clashes, skips files that are open, and can be undone.</li>
      <li>Uninstall runs the program's own uninstaller. Leftover registry keys are exported to a .reg backup before removal and can be restored below.</li>
      <li>Startup switches use Windows' StartupApproved setting (like Task Manager) and are reversible. The app never elevates itself; admin needs your UAC click.</li>
      <li>Protection checks, app update checks and the monitor only read. Recommendations are off by default, and every Apply shows a confirm card first.</li>
      <li>AI suggestions only get sizes, names and ids (never file contents or keys), can only pick actions this PC can actually run, can never empty the Recycle Bin or pick files to delete, and are re-checked by the app before they're shown.</li>
    </ul></div>
  <div class="card" id="regCard"></div>
  <div class="card log" id="logList" style="padding:0"></div>
  <div class="more" id="logPath"></div>
</section>
</main>
</div>

<div class="selbar" id="selbar" hidden><span><b id="selN">0</b> selected &middot; <b id="selSize">0 B</b></span>
  <button class="ghost" id="selClear">Clear</button><button class="btn danger" id="selRecycle">Move to Recycle Bin… <kbd>Del</kbd></button></div>

<div class="modal-back" id="modal" hidden><div class="modal" id="modalBox"></div></div>
<div class="modal-back" id="kb" hidden><div class="modal wide">
  <div class="mh"><div class="mi k"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="2.5" y="6" width="19" height="12" rx="2.5"/><path d="M6.5 10h.01M10 10h.01M13.5 10h.01M17 10h.01M7.5 14h9"/></svg></div><h2>Keyboard shortcuts</h2><button class="ghost" id="kbClose">Close <kbd>Esc</kbd></button></div>
  <div class="kgrid">
    <div><div class="ksec">Anywhere in Windows</div>
      <div class="krow">Open PC Cleanup<span class="keys"><kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>C</kbd></span></div>
      <div class="ksec">Go to</div>
      <div class="krow">Dashboard<span class="keys"><kbd>1</kbd></span></div>
      <div class="krow">Scan &amp; disk map<span class="keys"><kbd>2</kbd></span></div>
      <div class="krow">Cleanup<span class="keys"><kbd>3</kbd></span></div>
      <div class="krow">Organize<span class="keys"><kbd>4</kbd></span></div>
      <div class="krow">Applications<span class="keys"><kbd>5</kbd></span></div>
      <div class="krow">Protection<span class="keys"><kbd>6</kbd></span></div>
      <div class="krow">Startup<span class="keys"><kbd>7</kbd></span></div>
      <div class="krow">Monitor<span class="keys"><kbd>8</kbd></span></div>
      <div class="krow">Activity &amp; safety<span class="keys"><kbd>9</kbd></span></div>
      <div class="krow">Settings &amp; AI<span class="keys"><kbd>,</kbd></span></div>
      <div class="krow">Scan result tabs<span class="keys"><kbd>Shift</kbd>+<kbd>1</kbd>…<kbd>4</kbd></span></div>
    </div>
    <div><div class="ksec">Actions</div>
      <div class="krow">Smart Scan / rescan / refresh this tab<span class="keys"><kbd>Ctrl</kbd>+<kbd>R</kbd> or <kbd>F5</kbd></span></div>
      <div class="krow">Search (Apps, Monitor) / folder box<span class="keys"><kbd>/</kbd></span></div>
      <div class="krow">Recycle selected files<span class="keys"><kbd>Del</kbd></span></div>
      <div class="krow">Up one folder in the disk map<span class="keys"><kbd>Backspace</kbd></span></div>
      <div class="krow">Undo the last organize<span class="keys"><kbd>Ctrl</kbd>+<kbd>Z</kbd></span></div>
      <div class="krow">Confirm a dialog<span class="keys"><kbd>Enter</kbd></span></div>
      <div class="krow">Cancel a scan / close a dialog<span class="keys"><kbd>Esc</kbd></span></div>
      <div class="krow">This list<span class="keys"><kbd>?</kbd></span></div>
    </div>
  </div>
  <div class="knote">Tip: the Desktop shortcut "PC Cleanup" also opens the app. Every delete, uninstall, startup switch or end task asks you to confirm first.</div>
</div></div>
<div class="snack" id="snack"></div>

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtB=n=>{n=+n||0;const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<4){n/=1024;i++}return (i?n.toFixed(n>=100?0:1):n)+" "+u[i]};
const fmtN=n=>(+n||0).toLocaleString();
const fdate=t=>{const d=new Date(t*1000);return d.toLocaleDateString(undefined,{year:"numeric",month:"short",day:"numeric"})};
const base=p=>p.split(/[\\/]/).filter(Boolean).pop()||p;
const dirn=p=>{const i=Math.max(p.lastIndexOf("\\"),p.lastIndexOf("/"));return i>0?p.slice(0,i):p};
const CHECK='<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.2 4.2L19 7"/></svg>';
const COLORS=["#7c6cff","#2dd4bf","#6ea8fe","#ffa94d","#ff5d73","#3ddc97","#c084fc","#f472b6","#facc15","#38bdf8","#a3e635","#fb923c"];
const ICONS={Images:'<rect x="3" y="4" width="18" height="16" rx="3"/><circle cx="9" cy="10" r="2"/><path d="M21 16l-5-5-9 9"/>',PDFs:'<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M9 15h6"/>',
Documents:'<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>',Spreadsheets:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 10h18M3 15h18M9 4v16"/>',
Archives:'<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M12 3v4M12 9v2M12 13v2"/>',Installers:'<path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 21h14"/>',Video:'<rect x="3" y="5" width="14" height="14" rx="2"/><path d="M17 10l4-2v8l-4-2"/>',
Audio:'<path d="M9 18V5l11-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="17" cy="16" r="3"/>',Code:'<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"/>',Other:'<circle cx="12" cy="12" r="9"/><path d="M8 12h.01M12 12h.01M16 12h.01"/>',
date:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>'};
const svg=(inner,sw)=>`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw||2}" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;

async function api(p){const r=await fetch(p);const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||("HTTP "+r.status));return j}
async function post(p,b){const r=await fetch(p,{method:"POST",headers:{"X-PCClean":"1","Content-Type":"application/json"},body:JSON.stringify(b||{})});
  const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||("HTTP "+r.status));return j}
let snackT;function snack(msg,err){const s=$("#snack");s.textContent=msg;s.className="snack show"+(err?" err":"");clearTimeout(snackT);snackT=setTimeout(()=>s.className="snack",err?5200:3600)}
function poll(id,tick){return new Promise((res,rej)=>{const go=async()=>{try{const j=await api("/api/job?id="+id);tick&&tick(j);if(j.done){j.error?rej(new Error(j.error)):res(j)}else setTimeout(go,350)}catch(e){rej(e)}};go()})}

const S={st:null,view:"scan",sub:"map",sel:new Map(),dir:null,largest:[],dups:[],old:null,scanJob:null,cats:null,catSel:new Set(),dry:true,rule:"type",skipLinks:true,plan:null,planSel:new Set(),measuring:false};

/* ---------------- navigation */
function show(v){if(!VIEWS.includes(v)&&v!=="settings")v="dashboard";const prev=S.view;S.view=v;
  $$(".nav").forEach(b=>b.classList.toggle("on",b.dataset.view===v));$$(".view").forEach(x=>x.classList.toggle("on",x.id==="v-"+v));
  history.replaceState(null,"","#"+v);updSel();if(prev==="monitor"&&v!=="monitor")stopMon();
  if(v==="activity"){loadLog();loadRegBk()} if(v==="cleanup"&&!S.cats&&!S.measuring)measure(); if(v==="organize"){renderUndo();loadRules()}
  if(v==="dashboard")loadDash(); if(v==="apps")loadApps(); if(v==="protection")loadProt(); if(v==="startup")loadStartup(); if(v==="monitor")startMon(); if(v==="settings")loadSettings()}
$$(".nav").forEach(b=>b.onclick=()=>show(b.dataset.view));

/* ---------------- drives */
function ring(pct){const r=24,c=2*Math.PI*r,col=pct>90?"#ff5d73":pct>75?"#ffa94d":"url(#g1)";
  return `<div class="ring"><svg viewBox="0 0 58 58"><defs><linearGradient id="g1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2dd4bf"/><stop offset="1" stop-color="#7c6cff"/></linearGradient></defs>
  <circle cx="29" cy="29" r="${r}" stroke="#ffffff10" stroke-width="7" fill="none"/><circle cx="29" cy="29" r="${r}" stroke="${col}" stroke-width="7" fill="none" stroke-linecap="round" stroke-dasharray="${c*pct/100} ${c}"/></svg><b>${Math.round(pct)}%</b></div>`}
function renderDrives(){const d=S.st.drives||[];
  $("#drives").innerHTML=d.map(x=>{const pct=x.total?x.used/x.total*100:0;return `<div class="card drive">${ring(pct)}<div class="dt"><b>${esc(x.label)} (${esc(x.root.replace(/\\$/,""))})</b><small>${fmtB(x.free)} free of ${fmtB(x.total)}</small><small>${fmtB(x.used)} used</small></div></div>`}).join("");
  $("#sdrives").innerHTML='<div class="sect" style="padding-left:6px">Drives</div>'+d.map(x=>{const pct=x.total?x.used/x.total*100:0;return `<div class="sdrive"><div class="t"><b>${esc(x.root.replace(/\\$/,""))}</b><span>${fmtB(x.free)} free</span></div><div class="mbar"><i class="${pct>90?"hot":""}" style="width:${pct}%"></i></div></div>`}).join("")}

/* ---------------- scan */
function scanChips(){const st=S.st,cur=$("#scanPath").value;
  const picks=[["Profile",st.home],["Downloads",st.downloads],["Desktop",st.desktop],["Documents",st.documents]];
  $("#scanChips").innerHTML=picks.map(([n,p])=>`<button class="chip ${cur===p?"on":""}" data-p="${esc(p)}">${esc(n)}</button>`).join("");
  $$("#scanChips .chip").forEach(c=>c.onclick=()=>{$("#scanPath").value=c.dataset.p;scanChips()})}
$("#scanPath").addEventListener("input",scanChips);
$("#scanPath").addEventListener("keydown",e=>{if(e.key==="Enter")startScan()});
async function startScan(){if(S.scanJob)return;const path=$("#scanPath").value.trim();
  try{const j=await post("/api/scan/start",{path});watchScan(j.id)}catch(e){snack(e.message,1)}}
async function watchScan(id){S.scanJob=id;$("#scanProg").hidden=false;$("#scanBtn").disabled=true;
  try{const j=await poll(id,j=>{const p=j.progress||{};const bar=$("#scanBar");
      if(p.phase==="hash"&&p.hash_total){bar.classList.remove("indet");bar.querySelector("i").style.width=Math.min(100,p.hashed/p.hash_total*100)+"%";
        $("#scanPText").textContent=`Checking ${fmtN(p.dup_candidates)} possible duplicates… ${fmtB(p.hashed)} of ${fmtB(p.hash_total)}`}
      else{bar.classList.add("indet");$("#scanPText").textContent=`${fmtN(p.files)} files · ${fmtB(p.bytes)} · ${p.current||""}`}});
    if(j.cancelled||!j.result){snack("Scan cancelled")}else{snack(`Scan done in ${j.result.seconds}s`);await loadScan()}}
  catch(e){snack(e.message,1)}
  S.scanJob=null;$("#scanProg").hidden=true;$("#scanBtn").disabled=false}
$("#scanBtn").onclick=startScan;
$("#scanCancel").onclick=()=>S.scanJob&&post("/api/job/cancel",{id:S.scanJob});

async function loadScan(){const st=await api("/api/state");S.st=st;renderDrives();if(!st.scan)return;
  S.sel.clear();const [dir,lg,dp,od]=await Promise.all([api("/api/scan/dir"),api("/api/scan/largest"),api("/api/scan/dups"),api("/api/scan/old?days="+st.settings.old_days)]);
  S.dir=dir;S.largest=lg.items;S.dups=dp.groups;S.old=od;renderScan()}
function renderScan(){const s=S.st.scan;$("#scanEmpty").hidden=!!s;$("#scanRes").hidden=!s;if(!s)return;
  $("#scanStats").innerHTML=[["Scanned",fmtB(s.size),`${esc(base(s.root))} · ${s.finished}`],["Files",fmtN(s.files),`${fmtN(s.dirs)} folders · ${s.seconds}s`],
    ["Cloud-only (OneDrive)",fmtB(s.cloud),"not on this disk"],["Duplicates",fmtB(s.dup_waste),`${fmtN(s.dup_groups)} sets reclaimable`]]
    .map(([a,b,c])=>`<div class="card stat"><small>${a}</small><b>${b}</b><em>${c}</em></div>`).join("");
  const tabs=[["map","Disk map",""],["large","Largest files",S.largest.length],["dups","Duplicates",S.dups.length],["old","Old downloads",S.old?S.old.count:0]];
  $("#subtabs").innerHTML=tabs.map(([k,n,c],i)=>`<button class="subtab ${S.sub===k?"on":""}" data-k="${k}" title="Shift+${i+1}">${n}${c!==""?`<span class="n">${fmtN(c)}</span>`:""}</button>`).join("");
  $$("#subtabs .subtab").forEach(b=>b.onclick=()=>{S.sub=b.dataset.k;renderScan()});
  ["map","large","dups","old"].forEach(k=>$("#st-"+k).hidden=S.sub!==k);
  ({map:renderMap,large:renderLarge,dups:renderDups,old:renderOld})[S.sub]();updSel()}
function renderMap(){const d=S.dir;if(!d)return;const tot=Math.max(1,d.size+d.cloud);
  const kids=d.children.slice();if(d.own.files)kids.push({name:"(files in this folder)",path:null,size:d.own.size,cloud:d.own.cloud,files:d.own.files,own:1});
  kids.sort((a,b)=>(b.size+b.cloud)-(a.size+a.cloud));
  const top=kids.slice(0,12);
  let h=`<div class="crumbs">${d.crumbs.map((c,i)=>(i?"<i>›</i>":"")+`<button data-p="${esc(c.path)}">${esc(c.name)}</button>`).join("")}<span style="flex:1"></span><span style="color:var(--muted)">${fmtB(d.size)} on disk${d.cloud?` · ${fmtB(d.cloud)} cloud-only`:""} · ${fmtN(d.files)} files</span></div>`;
  h+=`<div class="strip">${top.filter(k=>k.size>0).map((k,i)=>`<div class="seg" data-p="${k.path?esc(k.path):""}" title="${esc(k.name)} · ${fmtB(k.size)}" style="flex:${k.size} 1 0;background:linear-gradient(160deg,${COLORS[i%12]},${COLORS[i%12]}aa)">${k.size/tot>.07?esc(k.name):""}</div>`).join("")}</div>`;
  h+=`<div class="dlist">`+kids.map((k,i)=>{const pct=(k.size+k.cloud)/tot*100;return `<div class="drow" data-p="${k.path?esc(k.path):""}"><span class="sw" style="background:${i<12?COLORS[i%12]:"#3a4257"}"></span>
   <span class="nm">${esc(k.name)}${k.cloud?`<span class="tag">${fmtB(k.cloud)} cloud</span>`:""}${k.denied?`<span class="tag warn">no access</span>`:""}</span>
   <div class="mbar"><i style="width:${Math.max(.5,pct)}%;background:${i<12?COLORS[i%12]:"#3a4257"}"></i></div><span class="sz">${fmtB(k.size)}</span><span class="ct">${fmtN(k.files)} files</span></div>`}).join("")+`</div>`;
  if(d.more)h+=`<div class="more">+ ${d.more} smaller folders</div>`;
  $("#st-map").innerHTML=h;
  $$("#st-map [data-p]").forEach(x=>x.onclick=()=>{if(x.dataset.p)drill(x.dataset.p)})}
async function drill(p){try{S.dir=await api("/api/scan/dir?path="+encodeURIComponent(p));renderMap()}catch(e){snack(e.message,1)}}
function canPick(f){return !f.cloud&&!f.protected}
function fileRow(f,extra){const on=S.sel.has(f.path),ok=canPick(f);
  return `<tr class="${ok?"pick":""} ${on?"sel":""}" data-p="${esc(f.path)}" data-s="${f.size||0}"><td style="width:34px"><span class="cb ${ok?"":"off"}">${CHECK}</span></td>
   <td><div class="fname">${esc(base(f.path))}${f.cloud?'<span class="tag">cloud-only</span>':""}${f.protected?'<span class="tag warn">protected</span>':""}${extra||""}</div><div class="fdir">${esc(dirn(f.path))}</div></td>
   <td class="num">${fmtB(f.size)}</td><td class="num" style="color:var(--muted)">${fdate(f.mtime)}</td></tr>`}
function wireRows(root){$$(root+" tr.pick").forEach(tr=>tr.onclick=()=>{const p=tr.dataset.p;S.sel.has(p)?S.sel.delete(p):S.sel.set(p,+tr.dataset.s);tr.classList.toggle("sel");updSel()})}
function renderLarge(){$("#st-large").innerHTML=`<div class="card" style="padding:6px 8px"><table><thead><tr><th></th><th>File</th><th class="num">Size</th><th class="num">Modified</th></tr></thead><tbody>${S.largest.map(f=>fileRow(f)).join("")}</tbody></table></div>`;wireRows("#st-large")}
function renderDups(){if(!S.dups.length){$("#st-dups").innerHTML=`<div class="card empty"><h3>No duplicates found</h3><div>Files of ${S.st.settings.dup_min_kb} KB or more were compared by size, then by content.</div></div>`;return}
  const tot=S.dups.reduce((a,g)=>a+g.size*(g.files.length-1),0);
  let h=`<div class="card row" style="margin-bottom:12px;gap:10px;flex-wrap:wrap"><div style="flex:1;min-width:260px"><b>${fmtN(S.dups.length)} duplicate sets · ${fmtB(tot)} in extra copies</b><div class="note">Matched by size, then a quick hash, then a full content hash. One copy of every set is always kept. Cloud-only and protected copies are never selected. Selected copies go to the Recycle Bin.</div></div>
    <button class="ghost" id="autoDupOld">${svg('<path d="M5 12.5l4.2 4.2L19 7"/>')}Select extras · keep oldest</button><button class="ghost" id="autoDupNew">${svg('<path d="M5 12.5l4.2 4.2L19 7"/>')}Select extras · keep newest</button><button class="ghost" id="autoDupClr">Clear</button></div>`;
  h+=S.dups.map(g=>{const n=g.files.length;return `<div class="card group"><div class="gh"><b>${esc(base(g.files[0].path))}</b><small>${n} copies · ${fmtB(g.size)} each</small><span class="tag ok">${fmtB(g.size*(n-1))} reclaimable</span></div>
    <table><tbody>${g.files.map((f,i)=>fileRow({...f,size:g.size},(i===0?'<span class="tag ok">oldest</span>':"")+(i===n-1?'<span class="tag">newest</span>':"")+`<button class="ghost mini" style="margin-left:8px;padding:2px 7px" data-open="${esc(f.path)}" title="Show in Explorer">${ICO_OPEN}</button>`)).join("")}</tbody></table></div>`}).join("");
  $("#st-dups").innerHTML=h;wireRows("#st-dups");
  $$("#st-dups [data-open]").forEach(b=>b.onclick=e=>{e.stopPropagation();openLoc(b.dataset.open)});
  const auto=newest=>{S.dups.forEach(g=>{const keep=newest?g.files.length-1:0;g.files.forEach((f,i)=>{S.sel.delete(f.path);if(i!==keep&&canPick(f))S.sel.set(f.path,g.size)})});renderDups();updSel()};
  $("#autoDupOld").onclick=()=>auto(false);$("#autoDupNew").onclick=()=>auto(true);
  $("#autoDupClr").onclick=()=>{S.dups.forEach(g=>g.files.forEach(f=>S.sel.delete(f.path)));renderDups();updSel()}}
function renderOld(){const o=S.old;if(!o){$("#st-old").innerHTML="";return}
  let h=`<div class="card row" style="justify-content:space-between"><div>Files (64 KB and up) in <b>${esc(o.folder)}</b>${S.st.scan.downloads_recursive?"":" (top level only — scan your profile or Downloads to include subfolders)"} not changed in <input class="num-in" id="oldDays" type="number" min="0" value="${o.days}"> days</div><div><b>${fmtN(o.count)}</b> files · <b>${fmtB(o.size)}</b></div></div>`;
  h+=o.items.length?`<div class="card" style="padding:6px 8px"><table><thead><tr><th></th><th>File</th><th class="num">Size</th><th class="num">Modified</th></tr></thead><tbody>${o.items.map(f=>fileRow(f)).join("")}</tbody></table></div>`:`<div class="card empty"><h3>Nothing that old</h3><div>Your Downloads folder is tidy.</div></div>`;
  $("#st-old").innerHTML=h;wireRows("#st-old");
  $("#oldDays").onchange=async e=>{const d=Math.max(0,+e.target.value||0);await post("/api/settings",{old_days:d});S.st.settings.old_days=d;S.old=await api("/api/scan/old?days="+d);renderScan()}}
function updSel(){const n=S.sel.size;$("#selbar").hidden=!(n&&S.view==="scan");$("#selN").textContent=fmtN(n);$("#selSize").textContent=fmtB([...S.sel.values()].reduce((a,b)=>a+b,0))}
$("#selClear").onclick=()=>{S.sel.clear();renderScan()};
$("#selRecycle").onclick=recycleSel;
async function recycleSel(){if(!S.sel.size)return;const paths=[...S.sel.keys()],tot=[...S.sel.values()].reduce((a,b)=>a+b,0);
  const ok=await confirmBox({icon:"danger",title:"Move to the Recycle Bin?",ok:`Move ${paths.length} file${paths.length>1?"s":""} to Recycle Bin`,danger:1,
    html:`<div class="big">${fmtB(tot)}</div>${paths.length} file${paths.length>1?"s":""} will go to the Recycle Bin. You can restore them from there.<ul>${paths.slice(0,8).map(p=>`<li>${esc(p)}</li>`).join("")}${paths.length>8?`<li>+ ${paths.length-8} more</li>`:""}</ul>`});
  if(!ok)return;
  try{const r=await post("/api/files/recycle",{paths,confirm:"yes"});
    snack(`${r.ok.length} file(s) moved to the Recycle Bin (${fmtB(r.freed)})`+(r.failed.length+r.refused.length?` · ${r.failed.length+r.refused.length} skipped`:""),r.failed.length+r.refused.length&&!r.ok.length);
    await loadScan()}catch(e){snack(e.message,1)}}

/* ---------------- cleanup */
const CAT_IC={temp:['<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 14l2 2 4-4"/>',"#2dd4bf"],
 edge:['<circle cx="12" cy="12" r="9"/><path d="M3.5 14c2-4 8-5 11-2 2 2 1 5-1 5.5M12 3c4 0 8 3 8 8"/>',"#38bdf8"],
 chrome:['<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M12 8.5h8.5M9 13.8L4.8 6.5M15 13.8l-4.2 7.3"/>',"#facc15"],
 thumbs:['<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="8" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/><rect x="13" y="13" width="8" height="8" rx="2"/>',"#c084fc"],
 firefox:['<circle cx="12" cy="12" r="9"/><path d="M7 7c2-1 5 0 6 2 2-1 4 1 4 3a5 5 0 0 1-10 0"/>',"#fb923c"],
 wer:['<path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',"#ff5d73"],
 shader:['<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>',"#3ddc97"],
 logs:['<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',"#6ea8fe"],
 devcache:['<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"/>',"#a3e635"],
 _:['<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>',"#8b93a7"]};
async function measure(){if(S.measuring)return;S.measuring=true;$("#cats").innerHTML=`<div class="card" style="grid-column:span 2"><div class="bar indet"><i></i></div><div class="ptext"><span id="mText">Measuring temp and cache folders…</span></div></div>`;
  try{const j=await post("/api/cleanup/measure");const r=await poll(j.id,j=>{const t=$("#mText");if(t&&j.progress.current)t.textContent="Measuring "+j.progress.current+"…"});
    S.cats=r.result;if(!S.catSel.size)S.cats.cats.forEach(c=>{if(c.default&&!c.running&&c.size)S.catSel.add(c.id)});renderCats()}
  catch(e){snack(e.message,1)}S.measuring=false}
function renderCats(){const r=S.cats;if(!r)return;const main=r.cats.filter(c=>!c.review_only),rev=r.cats.filter(c=>c.review_only);
  $("#cats").innerHTML=main.map(c=>{const dis=c.running||!c.files;const on=S.catSel.has(c.id)&&!dis;const [ic,col]=CAT_IC[c.id]||CAT_IC._;
   const note=(c.running?`<span class="tag warn">Browser is open — close it to clean</span>`:!c.present?`<span class="tag">Not installed</span>`:!c.files?`<span class="tag ok">Already clean</span>`:"")+(c.optin?`<span class="tag">opt-in</span>`:"");
   return `<div class="card cat ${on?"on":""} ${dis?"dis":""}" data-id="${c.id}"><span class="cb ${dis?"off":""} ${on?"on":""}">${CHECK}</span>
    <div class="ic" style="background:${col}1f;color:${col}">${svg(ic)}</div><div class="ct"><b>${esc(c.name)}</b><small>${esc(c.desc)}</small><div style="margin-top:7px">${note}</div></div>
    <div class="cs"><b>${fmtB(c.size)}</b><small>${fmtN(c.files)} files</small></div></div>`}).join("");
  $$("#cats .cat").forEach(x=>x.onclick=()=>{if(x.classList.contains("dis"))return;const id=x.dataset.id;S.catSel.has(id)?S.catSel.delete(id):S.catSel.add(id);renderCats()});
  renderCatReview(r,rev);
  const sel=main.filter(c=>S.catSel.has(c.id)&&!c.running&&c.files);
  $("#catTotal").textContent=sel.length?`${fmtB(sel.reduce((a,c)=>a+c.size,0))} · ${fmtN(sel.reduce((a,c)=>a+c.files,0))} files`:"Nothing selected";
  $("#cleanBtn").disabled=!sel.length;
  const rb=r.recycle;$("#rbText").textContent=rb.ok?(rb.items?`${fmtN(rb.items)} item${rb.items>1?"s":""} · ${fmtB(rb.size)}`:"Empty"):"Size unavailable";
  $("#emptyBtn").disabled=!(rb.ok&&rb.items)}
function renderCatReview(r,rev){const inst=r.installers;
  $("#instCard").innerHTML=inst&&inst.count?`<div class="card" id="instBox"><div class="row"><b style="flex:1">Old installers in Downloads</b><span class="tag warn">review first</span><b>${fmtB(inst.size)}</b></div>
    <div class="note">${fmtN(inst.count)} setup files (.exe, .msi…) older than ${inst.days} days in Downloads and its first level of subfolders. This app doesn't delete them from here: pick the ones you don't need in Scan › Old downloads and they go to the Recycle Bin.${inst.cloud_skipped?` ${fmtN(inst.cloud_skipped)} cloud-only files weren't counted.`:""}</div>
    <table class="tbl"><tbody>${inst.items.slice(0,12).map(x=>`<tr><td><div class="fname">${esc(base(x.path))}</div><small>${esc(dirn(x.path))}</small></td><td class="num">${fmtB(x.size)}</td><td class="num" style="color:var(--muted)">${fmtN(x.age_days)} days old</td><td class="act"><button class="ghost mini" data-open="${esc(x.path)}" title="Show in Explorer">${ICO_OPEN}</button></td></tr>`).join("")}</tbody></table>
    ${inst.count>12?`<div class="more">+ ${fmtN(inst.count-12)} more</div>`:""}<div class="applybar"><span class="sp"></span><button class="ghost mini" id="instGo">Open Scan › Old downloads</button></div></div>`:"";
  $("#catReview").innerHTML=rev.length?`<div class="card"><div class="row"><b style="flex:1">Review only — measured here, cleaned by Windows</b><button class="ghost mini" id="openStorage">Open Windows Storage settings</button></div>
    <table class="tbl"><tbody>${rev.map(c=>`<tr><td><div class="fname">${esc(c.name)}${c.needs_admin?'<span class="tag warn">needs admin</span>':""}</div><small>${esc(c.desc)}</small></td>
      <td class="num">${c.size?fmtB(c.size):c.denied?'<span class="tag">can\'t measure without admin</span>':'<span class="tag ok">empty</span>'}</td>
      <td class="act">${c.roots&&c.roots[0]?`<button class="ghost mini" data-open="${esc(c.roots[0])}" title="Open folder">${ICO_OPEN}</button>`:""}</td></tr>`).join("")}</tbody></table></div>`:"";
  $$("#instCard [data-open],#catReview [data-open]").forEach(b=>b.onclick=()=>openLoc(b.dataset.open));
  const g=$("#instGo");if(g)g.onclick=()=>goReview({tab:"scan",sub:"old"});
  const o=$("#openStorage");if(o)o.onclick=()=>post("/api/open/settings",{page:"storage"}).catch(e=>snack(e.message,1))}
$("#measureBtn").onclick=()=>{S.cats=null;measure()};
$("#dryToggle").onclick=()=>{S.dry=!S.dry;$("#dryToggle").classList.toggle("on",S.dry);$("#cleanBtn").textContent=S.dry?"Run dry run":"Clean now…";$("#cleanBtn").className="btn"+(S.dry?"":" danger")};
$("#cleanBtn").onclick=async()=>{const r=S.cats;if(!r)return;const sel=r.cats.filter(c=>S.catSel.has(c.id)&&!c.running&&c.files);if(!sel.length)return;
  const tot=sel.reduce((a,c)=>a+c.size,0);
  if(!S.dry){const ok=await confirmBox({icon:"danger",title:"Clean these files?",danger:1,ok:`Delete ${fmtB(tot)}`,
     html:`<div class="big">${fmtB(tot)}</div>These temp and cache files are deleted directly (they can't go to the Recycle Bin). Files in use are skipped.<ul>${sel.map(c=>`<li>${esc(c.name)} — ${fmtB(c.size)}, ${fmtN(c.files)} files</li>`).join("")}</ul>`});if(!ok)return}
  $("#cleanBtn").disabled=true;$("#cleanResult").innerHTML=`<div class="card"><div class="bar indet"><i></i></div><div class="ptext"><span id="cText">${S.dry?"Dry run…":"Cleaning…"}</span></div></div>`;
  try{const j=await post("/api/cleanup/run",{ids:sel.map(c=>c.id),dry:S.dry,confirm:S.dry?"":"yes"});
    const res=(await poll(j.id,j=>{const t=$("#cText");if(t&&j.progress.current)t.textContent=(S.dry?"Dry run: ":"Cleaning ")+j.progress.current+"…"})).result;
    $("#cleanResult").innerHTML=`<div class="card result ${res.dry?"dry":""}"><h3>${res.dry?"Dry run — nothing was deleted":"Cleanup finished"}</h3>
      <div>${res.dry?"Would free":"Freed"} <b>${fmtB(res.freed)}</b> from ${fmtN(res.deleted)} files${res.skipped?` · ${fmtN(res.skipped)} locked files skipped`:""}.</div>
      <ul>${res.report.map(x=>`<li><b>${esc(x.name)}</b>: ${x.note?esc(x.note):`${fmtN(x.deleted)} files, ${fmtB(x.freed)}${x.skipped?`, ${fmtN(x.skipped)} in use and skipped`:""}`}${(x.skipped_examples||[]).length?`<ul>${x.skipped_examples.slice(0,4).map(e=>`<li><small>${esc(base(e.path))} — ${esc(e.reason)}</small></li>`).join("")}</ul>`:""}</li>`).join("")}</ul>
      ${res.dry?'<div style="margin-top:8px;color:var(--muted);font-size:12.5px">Turn off Dry run to clean for real.</div>':""}</div>`;
    if(!res.dry){S.cats=null;measure();refreshDrives()}}
  catch(e){$("#cleanResult").innerHTML="";snack(e.message,1)}$("#cleanBtn").disabled=false};
$("#emptyBtn").onclick=async()=>{const rb=S.cats&&S.cats.recycle;if(!rb||!rb.items)return;
  const ok=await confirmBox({icon:"danger",title:"Empty the Recycle Bin?",danger:1,ok:"Empty permanently",typeWord:"EMPTY",
    html:`<div class="big">${fmtB(rb.size)}</div>${fmtN(rb.items)} item${rb.items>1?"s":""} will be <b>permanently deleted</b>. This can't be undone.`});if(!ok)return;
  try{const r=await post("/api/recycle/empty",{confirm:"EMPTY"});snack(r.ok?`Recycle Bin emptied (${fmtB(r.freed)})`:"Couldn't empty the Recycle Bin",!r.ok);S.cats=null;measure();refreshDrives()}catch(e){snack(e.message,1)}};
async function refreshDrives(){try{S.st=await api("/api/state");renderDrives()}catch(e){}}

/* ---------------- organize */
function orgChips(){const st=S.st,cur=$("#orgPath").value;
  $("#orgChips").innerHTML=[["Downloads",st.downloads],["Desktop",st.desktop],["Documents",st.documents]].map(([n,p])=>`<button class="chip ${cur===p?"on":""}" data-p="${esc(p)}">${esc(n)}</button>`).join("");
  $$("#orgChips .chip").forEach(c=>c.onclick=()=>{$("#orgPath").value=c.dataset.p;orgChips();preview()})}
$("#orgPath").addEventListener("input",orgChips);$("#orgPath").addEventListener("keydown",e=>{if(e.key==="Enter")preview()});
function setRule(r){S.rule=r;$$("#ruleSeg button").forEach(b=>b.classList.toggle("on",b.dataset.rule===r))}
$$("#ruleSeg button").forEach(b=>b.onclick=()=>{setRule(b.dataset.rule);post("/api/settings",{rule:S.rule});if(S.plan)preview()});
$("#linkToggle").onclick=()=>{S.skipLinks=!S.skipLinks;$("#linkToggle").classList.toggle("on",S.skipLinks);post("/api/settings",{skip_links:S.skipLinks});if(S.plan)preview()};
$("#previewBtn").onclick=preview;
async function preview(){const folder=$("#orgPath").value.trim();if(!folder)return snack("Pick a folder first",1);
  try{S.plan=await post("/api/organize/preview",{folder,rule:S.rule,skip_links:S.skipLinks});S.planSel=new Set(S.plan.items.map(i=>i.name));renderPlan()}
  catch(e){S.plan=null;$("#orgOut").innerHTML="";snack(e.message,1)}}
function renderPlan(){const p=S.plan;if(!p){$("#orgOut").innerHTML="";return}
  if(!p.items.length){$("#orgOut").innerHTML=`<div class="card empty"><div class="big">${svg('<path d="M5 12.5l4.2 4.2L19 7"/>',2.6).replace("currentColor","#fff")}</div><h3>Already tidy</h3><div>There are no loose files to sort in this folder.${p.skipped.length?` ${p.skipped.length} skipped.`:""}</div></div>`;return}
  const n=S.planSel.size;
  let h=`<div class="card"><div class="row" style="justify-content:space-between;margin-bottom:12px"><b>Preview (dry run) — nothing has moved yet</b><span style="color:var(--muted);font-size:12.5px">${fmtN(p.total)} files → ${p.groups.length} folders${p.skipped.length?` · ${p.skipped.length} skipped`:""}</span></div>
   <div class="gchips">${p.groups.map(([g,c])=>`<div class="gchip">${svg(ICONS[g]||ICONS.date)}<span>${esc(g)}</span><b>${c}</b></div>`).join("")}</div>
   <div style="max-height:420px;overflow:auto"><table><thead><tr><th style="width:34px"></th><th>File</th><th>Moves to</th><th class="num">Size</th></tr></thead><tbody>
   ${p.items.map(i=>`<tr class="pick ${S.planSel.has(i.name)?"sel":""}" data-n="${esc(i.name)}"><td><span class="cb">${CHECK}</span></td><td class="fname">${esc(i.name)}${i.cloud?'<span class="tag">cloud</span>':""}</td>
     <td><span class="arrow">→</span><span class="dest">${esc(i.to)}</span>${i.renamed?'<span class="tag warn">renamed, name taken</span>':""}</td><td class="num">${fmtB(i.size)}</td></tr>`).join("")}</tbody></table></div>
   ${p.skipped.length?`<details><summary>${p.skipped.length} file(s) skipped</summary><ul>${p.skipped.map(s=>`<li>${esc(s.name)} — ${esc(s.reason)}</li>`).join("")}</ul></details>`:""}
   <div class="applybar"><span class="sp">Only top-level files move. Subfolders stay where they are. Open files are skipped.</span><button class="btn" id="applyBtn" ${n?"":"disabled"}>Move ${fmtN(n)} file${n===1?"":"s"}…</button></div></div>`;
  $("#orgOut").innerHTML=h;
  $$("#orgOut tr.pick").forEach(tr=>tr.onclick=()=>{const k=tr.dataset.n;S.planSel.has(k)?S.planSel.delete(k):S.planSel.add(k);renderPlan()});
  $("#applyBtn").onclick=applyPlan}
async function applyPlan(){const p=S.plan;const names=p.items.filter(i=>S.planSel.has(i.name)).map(i=>i.name);if(!names.length)return;
  const ok=await confirmBox({icon:"move",title:"Organize this folder?",ok:`Move ${names.length} file${names.length>1?"s":""}`,
    html:`<div class="big">${fmtN(names.length)} files</div>in <b>${esc(p.folder)}</b> will move into ${p.groups.length} subfolder${p.groups.length>1?"s":""} (${p.rule==="date"?"by date":"by type"}). You can undo this with one click.`});if(!ok)return;
  try{const r=await post("/api/organize/apply",{folder:p.folder,rule:p.rule,skip_links:p.skip_links,names,confirm:"yes"});
    snack(`Moved ${r.moved} file(s)`+(r.failed.length?` · ${r.failed.length} skipped (in use)`:"")+" · Ctrl+Z to undo");
    await refreshUndo();await preview()}catch(e){snack(e.message,1)}}
async function refreshUndo(){try{S.st=await api("/api/state")}catch(e){}renderUndo()}
function renderUndo(){const u=S.st&&S.st.undo;$("#undoCard").innerHTML=u?`<div class="card undo"><div class="ic">${svg('<path d="M9 14L4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-3"/>')}</div>
  <div class="ut"><b>Last organize: ${fmtN(u.count)} file${u.count===1?"":"s"} in ${esc(base(u.folder))}</b><small>${esc(u.folder)} · ${esc(u.time)} · ${u.rule==="date"?"by date":"by type"}</small></div><button class="ghost" id="undoBtn">Undo <kbd>Ctrl Z</kbd></button></div>`:"";
  if(u)$("#undoBtn").onclick=undoOrg}
async function undoOrg(){const u=S.st&&S.st.undo;if(!u)return snack("Nothing to undo");
  const ok=await confirmBox({icon:"move",title:"Undo the last organize?",ok:"Put files back",html:`${fmtN(u.count)} file(s) go back to <b>${esc(u.folder)}</b>, and the empty folders it created are removed.`});if(!ok)return;
  try{const r=await post("/api/organize/undo");snack(`Restored ${r.restored} file(s)`+(r.failed.length?` · ${r.failed.length} couldn't be restored`:""),r.failed.length&&!r.restored);await refreshUndo();if(S.plan)preview()}catch(e){snack(e.message,1)}}

/* ---------------- activity */
async function loadLog(){try{const r=await api("/api/activity");
  $("#logList").innerHTML=r.items.length?r.items.map(x=>`<div class="lrow"><time>${esc(x.time)}</time><span class="kind k-${esc(x.kind.split(" ")[0])}">${esc(x.kind)}</span><span class="m">${esc(x.msg)}</span></div>`).join(""):`<div class="empty">No activity yet.</div>`;
  $("#logPath").textContent="Log file: "+r.path}catch(e){snack(e.message,1)}}
$("#logRefresh").onclick=loadLog;

/* ---------------- dialogs */
let modalRes=null;
function confirmBox(o){return new Promise(res=>{modalRes=res;const ic=o.icon==="move"?'<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M10 13h6M13 10l3 3-3 3"/>':'<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9L2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>';
  $("#modalBox").innerHTML=`<div class="mh"><div class="mi ${o.icon==="move"?"move":"danger"}">${svg(ic)}</div><h2>${esc(o.title)}</h2></div><div class="mbody">${o.html}</div>
   ${o.typeWord?`<div class="mtype"><div style="color:var(--muted);font-size:12.5px;margin-bottom:6px">Type <b style="color:#fff">${o.typeWord}</b> to confirm</div><input id="mType" autocomplete="off"></div>`:""}
   <div class="mfoot"><button class="ghost" id="mNo">Cancel <kbd>Esc</kbd></button><button class="btn ${o.danger?"danger":""}" id="mYes" ${o.typeWord?"disabled":""}>${esc(o.ok)}</button></div>`;
  $("#modal").hidden=false;$("#modal").dataset.word=o.typeWord||"";
  if(o.typeWord){const t=$("#mType");t.oninput=()=>$("#mYes").disabled=t.value.trim().toUpperCase()!==o.typeWord;setTimeout(()=>t.focus(),30)}else setTimeout(()=>$("#mYes").focus(),30);
  $("#mNo").onclick=()=>closeModal(false);$("#mYes").onclick=()=>closeModal(true)})}
function closeModal(v){$("#modal").hidden=true;const r=modalRes;modalRes=null;r&&r(v)}
$("#modal").onclick=e=>{if(e.target.id==="modal")closeModal(false)};
const kb=v=>$("#kb").hidden=!v;$("#kbBtn").onclick=()=>kb(1);$("#kbClose").onclick=()=>kb(0);$("#kb").onclick=e=>{if(e.target.id==="kb")kb(0)};

/* ================= v2: shared */
const VIEWS=["dashboard","scan","cleanup","organize","apps","protection","startup","monitor","activity"];
const RISK={low:"ok",medium:"warn",high:"bad",info:""};
async function runJob(path,body,tick){const j=await post(path,body||{});return poll(j.id,tick)}
const fmtRate=n=>fmtB(n)+"/s";
const pct=(a,b)=>b?Math.round(a/b*100):0;
const openLoc=p=>post("/api/open",{path:p}).catch(e=>snack(e.message,1));
const ICO_OPEN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></svg>';
function spark(vals,color,max){const w=300,h=54;const v=(vals.length?vals:[0]).map(x=>x==null?0:+x);const m=max||Math.max(1,...v);
  const pts=v.map((y,i)=>[v.length<2?w:i*(w/(v.length-1)),h-2-Math.min(1,y/m)*(h-6)]);const d=pts.map((p,i)=>(i?"L":"M")+p[0].toFixed(1)+" "+p[1].toFixed(1)).join("");
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><path d="${d}L${w} ${h}L0 ${h}Z" fill="${color}22"/><path d="${d}" fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>`}
function snackAct(msg,label,fn){const s=$("#snack");s.innerHTML=esc(msg)+`<button id="snackBtn">${esc(label)}</button>`;s.className="snack show";s.style.pointerEvents="auto";
  $("#snackBtn").onclick=()=>{s.className="snack";s.style.pointerEvents="";fn()};clearTimeout(snackT);snackT=setTimeout(()=>{s.className="snack";s.style.pointerEvents=""},10000)}
function upt(s){s=+s||0;const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+"d ":"")+h+"h "+m+"m"}
function adminUI(sel){const el=$(sel);if(!el)return;
  el.innerHTML=S.st.admin?'<span class="tag ok">Running as admin</span>':`<button class="ghost" data-adm>${svg('<path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/>')}Relaunch as admin…</button>`;
  const b=el.querySelector("[data-adm]");if(b)b.onclick=relaunchAdmin}
async function relaunchAdmin(){const ok=await confirmBox({icon:"move",title:"Relaunch as admin?",ok:"Relaunch",
  html:"Windows will ask you to approve (a UAC prompt you click). The app restarts with admin rights so it can handle all-users startup items, Program Files leftovers and HKLM registry keys. This window reconnects by itself. Nothing is changed by relaunching."});if(!ok)return;
  try{await post("/api/admin/relaunch");snack("Approve the Windows prompt… reconnecting");for(let i=0;i<40;i++){await new Promise(r=>setTimeout(r,1000));try{const st=await api("/api/state");if(st.admin){location.reload();return}}catch(e){}}}
  catch(e){snack(e.message,1)}}

/* ================= dashboard + recommendations */
const D={smart:null,recs:null,job:null};
async function loadDash(){try{D.smart=await api("/api/smart")}catch(e){}renderDash();loadRecs()}
function bigRing(score){const r=64,c=2*Math.PI*r,col=score>=80?"url(#gs)":score>=60?"#ffa94d":"#ff5d73";
  return `<div class="big"><svg viewBox="0 0 150 150"><defs><linearGradient id="gs" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2dd4bf"/><stop offset="1" stop-color="#7c6cff"/></linearGradient></defs>
   <circle cx="75" cy="75" r="${r}" stroke="#ffffff10" stroke-width="12" fill="none"/><circle cx="75" cy="75" r="${r}" stroke="${col}" stroke-width="12" fill="none" stroke-linecap="round" stroke-dasharray="${c*score/100} ${c}"/></svg><b>${score}</b></div>`}
function tile(view,icon,label,big,sub){return `<div class="card tile" data-go="${view}"><div class="th">${svg(icon)}${esc(label)}</div><b>${big}</b><em>${sub}</em></div>`}
function renderDash(){const s=D.smart&&D.smart.score!=null?D.smart:null;$("#dashEmpty").hidden=!!s||!!D.job;$("#dashRes").hidden=!s;if(!s)return;
  const lab=s.score>=85?"Looking good":s.score>=65?"A few things to review":"Needs attention";
  $("#dashScore").innerHTML=bigRing(s.score)+`<h3>${lab}</h3><p>Health score · Smart Scan ${esc(s.time)}</p>`;
  const p=s.protection||{},sm=p.summary||{},st=s.startup||{},h=s.health||{},u=s.updates||{},ap=s.apps||{};
  const av=p.defender_active?"Defender on":(p.products||[]).filter(x=>x.on).map(x=>x.name)[0]||(p.error?"Not checked":"No antivirus");
  const flags=(sm.ext_high||0)+(sm.startup||0)+(sm.tasks||0)+(sm.search||0);
  const disks=h.disks||[];const bad=disks.filter(d=>d.health&&d.health!=="Healthy");const b=h.battery;
  const last=(h.updates||[])[0];
  $("#dashTiles").innerHTML=
    tile("cleanup",'<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/>',"Space you could free",fmtB(s.reclaimable||0),s.space?`${fmtB(s.space.safe_now)} safe to clean now`:"temp, caches, Recycle Bin")+
    tile("protection",'<path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/>',"Protection",esc(av),`${sm.threats||0} threats · ${flags} to review`)+
    tile("startup",'<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/>',"Startup",`${st.enabled||0} on`,`${st.total||0} items · ${st.suspicious||0} suspicious`)+
    tile("apps",'<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/>',"Applications",`${ap.count||0} programs`,u.note&&!u.count?esc(u.note):`${u.count||0} updates available`)+
    tile("monitor",'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 15h.01M11 15h6"/>',"Disks & battery",bad.length?bad.length+" disk issue(s)":(disks.length?"Disks healthy":"Not checked"),
      (b&&b.health?`Battery ${b.health}% of design`:"No battery data")+(disks.length?` · ${disks.length} disk${disks.length>1?"s":""}`:""))+
    tile("dashboard",'<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',"Windows Update",(h.reboot||[]).length?"Restart pending":"No restart needed",last?`Last: ${esc((last.date||"").slice(0,10))}`:"History not readable");
  $$("#dashTiles [data-go]").forEach(t=>t.onclick=()=>{if(t.dataset.go!=="dashboard")show(t.dataset.go)});
  renderSpace(s.space);
  const iss=s.issues||[];
  $("#dashIssues").innerHTML=`<b>To review</b>`+(iss.length?`<ul class="issues">${iss.map(i=>`<li data-go="${esc(i.tab)}"><span class="dot ${i.sev==="bad"?"bad":""}"></span><span style="flex:1">${esc(i.text)}</span><span style="color:var(--muted)">›</span></li>`).join("")}</ul>`
    :`<ul class="issues"><li><span class="dot ok"></span>Nothing needs attention right now.</li></ul>`)+
    (h.updates&&h.updates.length?`<details><summary>Recent Windows updates</summary><ul>${h.updates.slice(0,6).map(x=>`<li>${esc((x.date||"").slice(0,10))} · ${esc(x.title)}${x.ok?"":" (failed)"}</li>`).join("")}</ul></details>`:"")+
    (disks.length?`<details><summary>Disks</summary><ul>${disks.map(d=>`<li>${esc(d.name)} · ${esc(d.media||"")} · ${fmtB(d.size)} · ${esc(d.health)}${d.temp!=null?` · ${d.temp}°C`:""}${d.wear!=null?` · wear ${d.wear}%`:""}${d.reliability?"":" · wear/temperature need admin"}</li>`).join("")}</ul></details>`:"")+
    (b?`<details><summary>Battery</summary><ul><li>${esc(b.maker)} ${esc(b.name)} · ${esc(b.chem)} · full charge ${fmtN(b.full)} of ${fmtN(b.design)} mWh (${b.health}%) · ${esc(b.cycles||"?")} cycles</li></ul></details>`:"");
  $$("#dashIssues [data-go]").forEach(t=>t.onclick=()=>{if(VIEWS.includes(t.dataset.go)&&t.dataset.go!=="dashboard")show(t.dataset.go)})}
const KIND={clean:["safe to clean","ok"],optin:["opt-in",""],permanent:["permanent","bad"],review:["review first","warn"],info:["included above",""]};
function renderSpace(sp){const sc=$("#spaceCard");if(!sp||!sp.items){sc.hidden=true;return}sc.hidden=false;const mx=Math.max(1,...sp.items.map(x=>x.size));
  sc.innerHTML=`<div class="row"><b style="flex:1;font-size:15px">Space you could free</b><span style="color:var(--muted);font-size:12px">click a row to go there</span></div>
  <div class="sbig"><div><small>Total you could free</small><b>${fmtB(sp.total)}</b></div><div><small>Safe to clean now</small><b style="color:var(--ok)">${fmtB(sp.safe_now)}</b></div>
   <div><small>All caches incl. opt-in</small><b>${fmtB(sp.clean)}</b></div><div><small>Recycle Bin (permanent)</small><b>${fmtB(sp.bin)}</b></div><div><small>Worth reviewing</small><b style="color:var(--warn)">${fmtB(sp.review)}</b></div></div>`+
  (sp.items.length?sp.items.map(x=>`<div class="sprow" data-go="${esc(x.tab)}" data-sub="${esc(x.sub||"")}"><span>${esc(x.label)}<span class="tag ${KIND[x.kind][1]}">${KIND[x.kind][0]}</span><small style="display:block;color:var(--muted);font-size:12px">${esc(x.note||"")}</small></span>
    <div class="mbar"><i style="width:${Math.max(1,x.size/mx*100)}%"></i></div><b>${fmtB(x.size)}</b></div>`).join(""):`<div class="note">Nothing worth freeing right now.</div>`)+
  `<div class="note" style="margin-top:8px">${esc(sp.note)}</div>`;
  $$("#spaceCard [data-go]").forEach(r=>r.onclick=()=>goReview({tab:r.dataset.go,sub:r.dataset.sub}))}
function goReview(o){const tab=o.tab&&VIEWS.includes(o.tab)?o.tab:"dashboard";
  if(tab==="apps"){A.tab=o.sub||"programs";if(o.filter&&A.tab==="programs")A.q=o.filter}
  if(tab==="scan"&&o.sub)S.sub=o.sub;
  if(tab==="startup")ST.filter="all";
  show(tab);
  if(tab==="scan"){if(S.st&&S.st.scan)renderScan();else if(o.sub)snack("Scan your profile first (Ctrl R) to list these files here.")}
  const f=(o.filter||(o.sub==="installers"?"Old installers in Downloads":"")).toLowerCase();if(f)flashText("#v-"+tab,f,0)}
function flashText(root,f,tries){const el=$$(root+" .fname, "+root+" b").find(e=>e.textContent.toLowerCase().includes(f));
  if(!el){if(tries<15)setTimeout(()=>flashText(root,f,tries+1),400);return}
  const row=el.closest("tr,.card,.rec")||el;row.classList.add("flash");row.scrollIntoView({block:"center",behavior:"smooth"});setTimeout(()=>row.classList.remove("flash"),3600)}
async function smartScan(){if(D.job)return;$("#smartProg").hidden=false;$("#smartBtn").disabled=true;$("#dashEmpty").hidden=true;
  try{const j0=await post("/api/smart/start");D.job=j0.id;
    const j=await poll(j0.id,j=>{const p=j.progress||{};$("#smartBar i").style.width=((p.step||0)/(p.steps||6)*100)+"%";$("#smartText").textContent=`Step ${p.step||0} of ${p.steps||6} · ${p.current||"Starting"}…`});
    if(j.result){D.smart=j.result;snack(`Smart Scan done · health ${j.result.score}/100`)}else snack("Smart Scan cancelled")}
  catch(e){snack(e.message,1)}
  D.job=null;$("#smartProg").hidden=true;$("#smartBtn").disabled=false;try{S.st=await api("/api/state")}catch(e){}renderDash();loadRecs(true)}
$("#smartBtn").onclick=smartScan;$("#smartCancel").onclick=()=>D.job&&post("/api/job/cancel",{id:D.job});
async function loadRecs(refresh){let ai;try{ai=await api("/api/ai")}catch(e){return}S.ai=ai;
  if(!ai.enabled){$("#recCard").innerHTML=`<div class="off"><div class="ic">${svg('<path d="M12 3l1.8 4.6L18.5 9l-4.7 1.6L12 15l-1.8-4.4L5.5 9l4.7-1.4z"/><path d="M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z"/>')}</div>
    <div class="t"><b>AI Recommendations</b><span class="tag">Off</span><small>Off — turn on in Settings. While it's off nothing runs automatically and no network calls are made.</small></div><button class="ghost" id="recOpen">Open Settings <kbd>,</kbd></button></div>`;
    $("#recOpen").onclick=()=>show("settings");return}
  if(refresh&&ai.provider==="openai")$("#recCard").innerHTML=`<b style="font-size:15px">Recommendations</b><div class="bar indet" style="margin-top:12px"><i></i></div><div class="ptext"><span>Asking ${esc(ai.model||"the AI")} with your scan results… up to ${ai.timeout||45} s. The built-in rules are shown if it doesn't answer.</span></div>`;
  try{D.recs=refresh?await post("/api/recs/refresh"):await api("/api/recs")}catch(e){return snack(e.message,1)}renderRecs()}
function recRow(it,i){const a=it.action||{},rv=a.type==="review";
  const tags=`<span class="tag ${it.source==="AI"?"src-ai":"src-rules"}">${it.source==="AI"?"AI":"Rules"}</span>`+(it.size?`<span class="chipsz">≈ ${fmtB(it.size)}</span>`:"")+
    (rv?'<span class="tag">review only</span>':`<span class="tag ${RISK[it.risk]}">${it.risk} risk</span><span class="tag ${it.reversible?"ok":"warn"}">${it.reversible?"undoable":it.permanent?"permanent":"can't be undone"}</span>`);
  return `<div class="rec"><div class="rt"><b>${esc(it.title)}</b>${tags}<small>${esc(it.reason)}${it.impact?` · <b style="color:var(--accent2);font-weight:600">${esc(it.impact)}</b>`:""}</small></div>
    <div class="ra">${rv?`<button class="ghost mini" data-rv="${i}">Review ›</button>`:`${it.tab&&it.tab!=="dashboard"?`<button class="ghost mini" data-rv="${i}">Open</button>`:""}<button class="btn mini ${it.risk==="high"?"danger":""}" data-ap="${i}">Apply…</button>`}</div></div>`}
function renderRecs(){const r=D.recs;if(!r)return;const safe=r.items.filter(i=>i.action&&i.action.type!=="review"&&i.risk==="low");
  const nAI=r.ai_count||0,nR=r.items.length-nAI;
  let h=`<div class="row" style="margin-bottom:4px"><b style="font-size:15px">Recommendations</b><span class="tag ${r.provider==="openai"?"src-ai":"src-rules"}">${r.provider==="openai"?"AI + rules":"rules"}</span>
    <span style="color:var(--muted);font-size:12px;flex:1">${esc(r.time||"")}${r.provider==="openai"?` · ${nAI} from AI${r.model?` (${esc(r.model)}${r.seconds!=null?`, ${r.seconds} s`:""})`:""}, ${nR} from rules`:""} · every Apply asks you to confirm first</span>
    <button class="ghost mini" id="recRefresh">Refresh</button><button class="btn mini" id="recSafe" ${safe.length?"":"disabled"}>Apply all safe (${safe.length})…</button></div>`;
  if(r.note)h+=`<div class="note" style="color:var(--warn)">${esc(r.note)}</div>`;
  if(!r.has_smart)h+=`<div class="note">Run a Smart Scan first so suggestions can use your real sizes and names.</div>`;
  h+=r.items.length?r.items.map(recRow).join(""):`<div class="empty" style="padding:24px">No recommendations right now. Run a Smart Scan for fresh data.</div>`;
  $("#recCard").innerHTML=h;
  $("#recRefresh").onclick=()=>loadRecs(true);$("#recSafe").onclick=()=>applyActions(safe.map(x=>x.action));
  $$("#recCard [data-rv]").forEach(b=>b.onclick=()=>{const it=r.items[+b.dataset.rv];const a=it.action||{};goReview(a.type==="review"?a:{tab:it.tab,sub:it.sub,filter:it.filter})});
  $$("#recCard [data-ap]").forEach(b=>b.onclick=()=>applyActions([r.items[+b.dataset.ap].action]))}
async function applyActions(actions){let pv;try{pv=await post("/api/recs/preview",{actions})}catch(e){return snack(e.message,1)}
  const html=pv.items.map(it=>`<div style="margin-bottom:12px"><b style="color:#fff">${esc(it.label)}</b> <span class="tag ${RISK[it.risk]}">${it.risk} risk</span><span class="tag ${it.reversible?"ok":"bad"}">${it.reversible?"reversible":"can't be undone"}</span>
    ${it.size?`<div class="big" style="font-size:19px">${fmtB(it.size)}</div>`:""}<ul>${it.targets.slice(0,8).map(t=>`<li>${esc(t)}</li>`).join("")}${it.targets.length>8?`<li>+ ${it.targets.length-8} more</li>`:""}</ul><div class="note">${esc(it.note)}</div></div>`).join("");
  const risky=pv.items.some(i=>!i.reversible);
  const ok=await confirmBox({icon:risky?"danger":"move",title:"Do you really want to do this action?",html,ok:pv.items.length>1?`Confirm all ${pv.items.length}`:"Confirm",danger:risky?1:0});
  if(!ok){snack("Cancelled. Nothing was changed.");return false}
  const results=[];
  for(const it of pv.items){let res;try{const r=await post("/api/recs/apply",{token:it.token,confirm:"yes"});res=await afterApply(it,r)}catch(e){res={label:it.label,ok:false,text:e.message}}results.push(res)}
  showResults(results);S.cats=null;ST.data=null;if(S.view==="dashboard")loadRecs(true);return true}
function showResults(res){const el=$("#recResult");if(!res.length)return;
  const html=`<div class="card result"><h3>What happened<span style="flex:1"></span><button class="ghost mini" id="resClose">Close</button></h3><ul class="resrow">${res.map(r=>`<li><b>${esc(r.label)}</b>${r.ok?"":'<span class="tag bad">not done</span>'} — ${esc(r.text)}${r.details&&r.details.length?`<ul>${r.details.slice(0,8).map(d=>`<li><small>${esc(d)}</small></li>`).join("")}</ul>`:""}</li>`).join("")}</ul></div>`;
  if(S.view==="dashboard"){el.innerHTML=html;$("#resClose").onclick=()=>el.innerHTML="";el.scrollIntoView({block:"nearest"})}
  else snack(res.map(r=>`${r.label}: ${r.text}`).join(" · "),res.some(r=>!r.ok))}
async function afterApply(it,r){const t=it.action.type,L=it.label;
  if(r.job){snack(L+"…");const j=await poll(r.job.id).catch(e=>({error:e.message}));const x=j.result||{};
    if(j.error)return {label:L,ok:false,text:j.error};
    if(t==="clean")return {label:L,ok:true,text:`Freed ${fmtB(x.freed)} from ${fmtN(x.deleted)} files${x.skipped?`; ${fmtN(x.skipped)} files were in use and skipped`:""}.`,
      details:(x.report||[]).flatMap(c=>[`${c.name}: ${c.note||`${fmtN(c.deleted)} files, ${fmtB(c.freed)}${c.skipped?`, ${fmtN(c.skipped)} skipped`:""}`}`].concat((c.skipped_examples||[]).slice(0,2).map(e=>`  skipped ${base(e.path)} (${e.reason})`)))};
    if(t==="defender_quickscan")return {label:L,ok:!!x.done,text:x.done?`Quick Scan finished in ${x.seconds}s`:x.note||"Stopped"};
    return {label:L,ok:!!x.ok,text:x.ok?`${x.id} updated.`:`${x.title} (${x.hex}). ${x.message}`}}
  if(r.undo==="organize"){snackAct(`Moved ${r.result.moved} file(s) into folders`,"Undo",undoOrg);return {label:L,ok:true,text:`Moved ${fmtN(r.result.moved)} file(s) into folders${(r.result.failed||[]).length?`; ${r.result.failed.length} skipped (open or locked)`:""}. Undo on the Organize tab (Ctrl+Z).`}}
  if(r.undo==="startup"){snackAct("Startup item switched off","Undo",()=>post("/api/startup/toggle",{id:r.id,enable:true,confirm:"yes"}).then(()=>{snack("Switched back on");ST.data=null}).catch(e=>snack(e.message,1)));
    return {label:L,ok:true,text:`${it.targets[0].split(" (")[0]} won't start at sign-in any more. Switch it back on from the Startup tab.`}}
  if(r.undo==="recycle"){const x=r.result;return {label:L,ok:x.ok.length>0,text:`${fmtN(x.ok.length)} file(s) moved to the Recycle Bin (${fmtB(x.freed)})${x.failed.length+x.refused.length?`; ${x.failed.length+x.refused.length} skipped`:""}.`,
    details:x.failed.concat(x.refused).slice(0,6).map(f=>`${base(f.path)}: ${f.reason}`)}}
  if(t==="empty_bin")return {label:L,ok:!!r.result.ok,text:r.result.ok?`Recycle Bin emptied (${fmtB(r.result.freed)}).`:"Windows couldn't empty the Recycle Bin."};
  return {label:L,ok:true,text:"Done."}}

/* ================= applications */
const A={tab:"programs",progs:null,q:"",sort:"name",store:null,wg:null,orph:null,left:null,leftSel:new Set(),busy:""};
async function loadApps(force){adminUI("#appsAdmin");
  if(!A.progs||force){try{A.progs=(await api("/api/apps"+(force?"?force=1":""))).programs}catch(e){snack(e.message,1)}}
  if(!A.wg){try{const w=await api("/api/winget");if(w.items)A.wg=w}catch(e){}}
  renderApps()}
function renderApps(){const tabs=[["programs","Programs",A.progs?A.progs.length:""],["store","Store apps",A.store?A.store.length:""],["updates","Updates",A.wg?A.wg.items.length:""],["orphans","Orphaned folders",A.orph?A.orph.count:""]];
  $("#appTabs").innerHTML=tabs.map(([k,n,c])=>`<button class="subtab ${A.tab===k?"on":""}" data-k="${k}">${n}${c!==""?`<span class="n">${fmtN(c)}</span>`:""}</button>`).join("");
  $$("#appTabs .subtab").forEach(b=>b.onclick=()=>{A.tab=b.dataset.k;renderApps();if(A.tab==="store"&&!A.store)loadStore()});
  renderLeft();({programs:renderProgs,store:renderStore,updates:renderUpdates,orphans:renderOrphans})[A.tab]()}
function renderProgs(){const q=A.q.toLowerCase();let list=(A.progs||[]).filter(p=>!q||(p.name+" "+p.publisher).toLowerCase().includes(q));
  const by={name:(a,b)=>a.name.localeCompare(b.name),size:(a,b)=>b.size-a.size,date:(a,b)=>(b.date||"").localeCompare(a.date||""),publisher:(a,b)=>a.publisher.localeCompare(b.publisher)}[A.sort];list=list.slice().sort(by);
  $("#appBody").innerHTML=`<div class="card" style="padding:12px 14px"><div class="row" style="margin-bottom:8px">
    <div class="pathbox search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg><input id="appQ" placeholder="Search programs or publishers" spellcheck="false" value="${esc(A.q)}"></div>
    <select class="sel" id="appSort">${[["name","Sort: name"],["size","Sort: size"],["date","Sort: install date"],["publisher","Sort: publisher"]].map(([k,n])=>`<option value="${k}" ${A.sort===k?"selected":""}>${n}</option>`).join("")}</select>
    <span style="flex:1;color:var(--muted);font-size:12.5px;text-align:right">${fmtN(list.length)} programs · Leftovers = read-only preview</span><button class="ghost mini" id="appReload">Reload</button></div>
    ${A.progs?`<table class="tbl"><thead><tr><th>Program</th><th>Version</th><th class="num">Size</th><th class="num">Installed</th><th></th></tr></thead><tbody>${list.slice(0,400).map(p=>`<tr>
     <td><div class="fname">${esc(p.name)}${p.hive==="HKLM"?'<span class="tag">all users</span>':'<span class="tag ok">this user</span>'}</div><small>${esc(p.publisher||"Unknown publisher")}${p.location?" · "+esc(p.location):""}</small></td>
     <td style="color:var(--muted)">${esc(p.version)}</td><td class="num">${p.size?fmtB(p.size):"–"}</td><td class="num" style="color:var(--muted)">${esc(p.date||"–")}</td>
     <td class="act"><button class="ghost mini" data-lo="${esc(p.id)}">Leftovers</button> <button class="btn danger mini" data-un="${esc(p.id)}" ${p.uninstall?"":"disabled"}>Uninstall…</button></td></tr>`).join("")}</tbody></table>`:`<div class="empty">Reading installed programs…</div>`}</div>`;
  const qi=$("#appQ");qi.oninput=()=>{A.q=qi.value;const pos=qi.selectionStart;renderProgs();const n=$("#appQ");n.focus();n.setSelectionRange(pos,pos)};
  $("#appSort").onchange=e=>{A.sort=e.target.value;renderProgs()};$("#appReload").onclick=()=>loadApps(true);
  $$("#appBody [data-lo]").forEach(b=>b.onclick=()=>previewLeftovers(b.dataset.lo));$$("#appBody [data-un]").forEach(b=>b.onclick=()=>uninstall(b.dataset.un))}
const progById=id=>(A.progs||[]).find(p=>p.id===id);
async function previewLeftovers(id){A.busy="Looking for leftovers (read-only)…";renderLeft();
  try{A.left=await post("/api/apps/leftovers",{id});A.leftSel=new Set()}catch(e){snack(e.message,1)}A.busy="";renderLeft();$("#main").scrollTo({top:0,behavior:"smooth"})}
async function uninstall(id){const p=progById(id);if(!p)return;
  const ok=await confirmBox({icon:"danger",danger:1,title:`Uninstall ${p.name}?`,ok:"Run its uninstaller",
    html:`Runs <b>${esc(p.name)}</b>'s own uninstaller. It may open its own window${p.hive==="HKLM"?" and Windows may ask for admin approval":""}.<ul><li>${esc(p.uninstall)}</li></ul>When it finishes, the app looks for leftover folders, registry keys and shortcuts and lists them for review. Nothing else is removed without another confirm.`});if(!ok)return;
  A.busy=`Waiting for ${p.name}'s uninstaller to finish…`;renderLeft();
  try{const j=await runJob("/api/apps/uninstall",{id,confirm:"yes"});A.left=j.result;A.leftSel=new Set(j.result.items.map((x,i)=>[x,i]).filter(([x])=>x.confidence>=85&&!x.needs_admin&&x.kind!=="task").map(([,i])=>i));
    snack(j.result.removed?`${p.name} was uninstalled. Review the leftovers below.`:"The program still looks installed.",!j.result.removed)}catch(e){snack(e.message,1)}
  A.busy="";A.progs=null;loadApps(true)}
function renderLeft(){const el=$("#appLeft");if(A.busy){el.innerHTML=`<div class="card lft"><div class="bar indet"><i></i></div><div class="ptext"><span>${esc(A.busy)}</span></div></div>`;return}
  const L=A.left;if(!L){el.innerHTML="";return}
  const canPickL=x=>["folder","shortcut","regkey"].includes(x.kind)&&!x.needs_admin&&!x.removed;
  const selSize=[...A.leftSel].reduce((a,i)=>a+(L.items[i]?L.items[i].size:0),0);
  el.innerHTML=`<div class="card lft"><div class="row"><div style="flex:1"><b>Leftovers of ${esc(L.program)}</b> <span class="tag">${L.items.length} found · ${fmtB(L.size)}</span>
     <div class="note">${esc(L.note||"")} Folders and shortcuts go to the Recycle Bin. Registry keys are exported to a .reg backup first and can be restored from Activity &amp; safety.</div></div>
     <button class="btn danger mini" id="lfRemove" ${A.leftSel.size?"":"disabled"}>Remove ${A.leftSel.size} selected…</button><button class="ghost mini" id="lfClose">Close</button></div>
    ${L.items.length?`<table class="tbl" style="margin-top:8px"><tbody>${L.items.map((x,i)=>`<tr class="${canPickL(x)?"pick":""} ${A.leftSel.has(i)?"sel":""}" data-i="${i}"><td style="width:34px"><span class="cb ${canPickL(x)?"":"off"}">${CHECK}</span></td>
      <td><div class="fname">${esc(x.path)}</div><small>${esc(x.why)}</small></td><td><span class="tag">${{folder:"folder",regkey:"registry",shortcut:"shortcut",task:"task"}[x.kind]}</span></td>
      <td><span class="tag ${x.confidence>=85?"ok":x.confidence>=60?"warn":"bad"}">${x.confidence}% match</span>${x.needs_admin?'<span class="tag warn">needs admin</span>':""}${x.removed?'<span class="tag ok">removed</span>':""}${x.kind==="task"?'<span class="tag">review only</span>':""}</td>
      <td class="num">${x.size?fmtB(x.size):""}</td><td class="act">${["folder","shortcut"].includes(x.kind)?`<button class="ghost mini" data-open="${esc(x.path)}" title="Open location">${ICO_OPEN}</button>`:""}</td></tr>`).join("")}</tbody></table>`
      :`<div class="empty" style="padding:20px">No leftovers found. Clean uninstall.</div>`}
    ${L.items.some(x=>x.needs_admin)&&!S.st.admin?`<div class="note" style="margin-top:8px">Items marked "needs admin" are in Program Files, ProgramData or HKLM. Use Relaunch as admin (top right) to remove them.</div>`:""}</div>`;
  $("#lfClose").onclick=()=>{A.left=null;renderLeft()};
  $$("#appLeft tr.pick").forEach(tr=>tr.onclick=e=>{if(e.target.closest("[data-open]"))return;const i=+tr.dataset.i;A.leftSel.has(i)?A.leftSel.delete(i):A.leftSel.add(i);renderLeft()});
  $$("#appLeft [data-open]").forEach(b=>b.onclick=()=>openLoc(b.dataset.open));
  $("#lfRemove").onclick=async()=>{const items=[...A.leftSel];const ok=await confirmBox({icon:"danger",danger:1,title:"Remove these leftovers?",ok:`Remove ${items.length}`,
      html:`<div class="big">${fmtB(selSize)}</div><ul>${items.slice(0,10).map(i=>`<li>${esc(L.items[i].path)}</li>`).join("")}${items.length>10?`<li>+ ${items.length-10} more</li>`:""}</ul>Folders and shortcuts go to the Recycle Bin. Registry keys are backed up to a .reg file first.`});if(!ok)return;
    try{const r=await post("/api/apps/remove-leftovers",{token:L.token,items,confirm:"yes"});L.items=r.items;A.leftSel.clear();
      snack(`Removed ${r.removed.length} item(s)`+(r.failed.length?` · ${r.failed.length} failed: ${r.failed[0].reason}`:""),r.failed.length&&!r.removed.length);renderLeft()}catch(e){snack(e.message,1)}}}
async function loadStore(){try{A.store=(await api("/api/apps/store")).items}catch(e){A.store=[];snack(e.message,1)}renderApps()}
function renderStore(){$("#appBody").innerHTML=`<div class="card" style="padding:6px 10px"><div class="note" style="padding:8px">Microsoft Store apps for your account (read-only list). Remove them from Settings › Apps if you don't need them.</div>
  ${A.store?(A.store.length?`<table class="tbl"><thead><tr><th>App</th><th>Publisher</th><th>Version</th></tr></thead><tbody>${A.store.map(a=>`<tr><td><div class="fname">${esc(a.name)}</div></td><td style="color:var(--muted)">${esc(a.publisher)}</td><td style="color:var(--muted)">${esc(a.version)}</td></tr>`).join("")}</tbody></table>`:`<div class="empty">No Store apps found.</div>`):`<div class="empty">Reading Store apps…</div>`}</div>`}
function renderUpdates(){const w=A.wg;
  $("#appBody").innerHTML=`<div class="card"><div class="row"><div style="flex:1"><b>App updates (winget)</b><div class="note">Checking only reads. Each upgrade asks you to confirm first and accepts that package's license.${w?` Last check ${esc(w.time)}.`:""}</div></div>
    <button class="btn teal" id="wgCheck" ${A.busyW?"disabled":""}>${A.busyW?"Checking…":"Check for updates"}</button></div>
    ${w?(w.items.length?`<table class="tbl" style="margin-top:10px"><thead><tr><th>App</th><th>Installed</th><th>Available</th><th></th></tr></thead><tbody>${w.items.map(u=>{const f=(w.failures||{})[u.id];return `<tr><td><div class="fname">${esc(u.name)}${f?'<span class="tag warn">last try failed</span>':""}</div><small>${esc(u.id)}</small>${f?`<small style="color:var(--warn)">${esc(f.title)} (${esc(f.hex)}): ${esc(f.message)}</small>`:""}</td>
      <td style="color:var(--muted)">${esc(u.version)}</td><td><span class="tag ok">${esc(u.available)}</span></td><td class="act">${u.applyable?`<button class="btn mini" data-up="${esc(u.id)}">${f?"Try again…":"Upgrade…"}</button>`:'<span class="tag">open winget</span>'}</td></tr>`}).join("")}</tbody></table>`
      :`<div class="empty" style="padding:24px">Everything winget knows about is up to date.${w.note?`<div class="note">${esc(w.note)}</div>`:""}</div>`):""}</div>`;
  $("#wgCheck").onclick=async()=>{A.busyW=1;renderUpdates();try{const j=await runJob("/api/winget/check");A.wg=await api("/api/winget")}catch(e){snack(e.message,1)}A.busyW=0;renderApps()};
  $$("#appBody [data-up]").forEach(b=>b.onclick=()=>applyActions([{type:"winget_upgrade",id:b.dataset.up}]))}
function renderOrphans(){const o=A.orph;
  $("#appBody").innerHTML=`<div class="card"><div class="row"><div style="flex:1"><b>Orphaned folders</b><div class="note">Folders in AppData and ProgramData whose names don't match any installed program. Low confidence and review-only: many belong to portable tools, Windows features or work software. Nothing here can be removed from the app.</div></div>
    <button class="btn teal" id="orScan" ${A.busyO?"disabled":""}>${A.busyO?"Scanning…":"Find orphaned folders"}</button></div>
    ${o?`<table class="tbl" style="margin-top:10px"><thead><tr><th>Folder</th><th class="num">Size</th><th class="num">Modified</th><th></th></tr></thead><tbody>${o.items.map(x=>`<tr><td><div class="fname">${esc(base(x.path))}<span class="tag bad">low confidence</span></div><small>${esc(x.path)}</small></td>
      <td class="num">${fmtB(x.size)}</td><td class="num" style="color:var(--muted)">${x.mtime?fdate(x.mtime):""}</td><td class="act"><button class="ghost mini" data-open="${esc(x.path)}">${ICO_OPEN}</button></td></tr>`).join("")}</tbody></table>`:""}</div>`;
  $("#orScan").onclick=async()=>{A.busyO=1;renderOrphans();try{const j=await runJob("/api/apps/orphans");A.orph=j.result}catch(e){snack(e.message,1)}A.busyO=0;renderApps()};
  $$("#appBody [data-open]").forEach(b=>b.onclick=()=>openLoc(b.dataset.open))}

/* ================= protection */
const P={data:null,busy:false};
async function loadProt(){if(!P.data){try{const r=await api("/api/protection");if(r.av)P.data=r}catch(e){}}renderProt()}
async function runProt(){if(P.busy)return;P.busy=true;$("#protProg").hidden=false;$("#protBtn").disabled=true;
  try{const j=await runJob("/api/protection/scan",{},j=>$("#protText").textContent=((j.progress||{}).current||"Checking")+"…");P.data=j.result;snack("Protection checks done")}catch(e){snack(e.message,1)}
  P.busy=false;$("#protProg").hidden=true;$("#protBtn").disabled=false;renderProt()}
$("#protBtn").onclick=runProt;
const sigTag=s=>`<span class="tag ${s==="Valid"?"ok":s==="Missing"||s==="HashMismatch"||s==="NotTrusted"?"bad":"warn"}">${s==="Valid"?"signed":s==="NotSigned"?"unsigned":esc((s||"unknown").toLowerCase())}</span>`;
function renderProt(){const d=P.data;if(!d){$("#protBody").innerHTML=`<div class="card empty"><div class="big">${svg('<path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/><path d="M9 12l2 2 4-4"/>',2.2)}</div><h3>Run the protection checks</h3><div>Antivirus status, Defender detections, browser extensions, home page and search hijacks, suspicious startup items and tasks, the hosts file and proxy settings. Read-only.</div></div>`;return}
  const s=d.summary,av=d.av,mp=av.mp||{};
  let h=`<div class="stats">${[["Threats",s.threats,s.threats?"unresolved":"none found"],["Risky extensions",s.ext_high,`${s.ext_medium} medium · ${s.extensions} total`],["Suspicious startup / tasks",s.startup+s.tasks,"unsigned in AppData/Temp"],["Browser settings",s.search,"hijack signs"]]
    .map(([a,b,c])=>`<div class="card stat"><small>${a}</small><b style="color:${b?"var(--warn)":"var(--ok)"}">${fmtN(b)}</b><em>${c}</em></div>`).join("")}</div>`;
  h+=`<div class="card"><div class="row"><b style="flex:1">Antivirus</b><span style="color:var(--muted);font-size:12px">Checked ${esc(d.time)}</span>
     <button class="btn mini" id="qsBtn" ${av.defender_active?"":"disabled"} title="${av.defender_active?"":"Defender isn't the active antivirus"}">Defender Quick Scan…</button></div>
    <table class="tbl" style="margin-top:6px"><tbody>${av.products.map(a=>`<tr><td><div class="fname">${esc(a.name)}</div><small>${esc(a.path||"")}</small></td><td>${a.on?'<span class="tag ok">on</span>':'<span class="tag">off / passive</span>'}${a.uptodate===false?'<span class="tag warn">out of date</span>':a.on?'<span class="tag ok">up to date</span>':""}</td></tr>`).join("")||`<tr><td>No antivirus reported to Windows Security Center.</td></tr>`}</tbody></table>
    <div class="note" style="margin-top:8px">Microsoft Defender: ${mp.ok?`mode <b>${esc(mp.mode)}</b> · real-time ${mp.rtp?"on":"off"} · signatures ${mp.sig>60000?"n/a":mp.sig+" day(s) old"} · last quick scan ${mp.qs>1e6?"never":mp.qs+" day(s) ago"}`:esc(mp.err||"status not readable")}</div>
    ${av.managed_note?`<div class="note" style="color:var(--warn);margin-top:6px">${esc(av.managed_note)}</div>`:""}</div>`;
  h+=`<div class="card"><b>Threat history</b>${av.threats.length?`<table class="tbl"><tbody>${av.threats.map(t=>`<tr><td><div class="fname">${esc(t.name)}</div><small>${esc((t.resources||[]).join(" · "))}</small></td><td>${t.resolved?'<span class="tag ok">resolved</span>':'<span class="tag bad">needs action</span>'}</td><td class="num" style="color:var(--muted)">${esc((t.time||"").replace("T"," "))}</td></tr>`).join("")}</tbody></table>`
    :`<div class="note" style="margin-top:6px">No detections in Microsoft Defender's history${av.defender_active?"":" (Defender is passive here, so detections by your organization's antivirus won't show)"}.</div>`}</div>`;
  const ex=d.extensions.slice().sort((a,b)=>({high:0,medium:1,low:2}[a.level]-{high:0,medium:1,low:2}[b.level]));
  h+=`<div class="card"><b>Browser extensions</b> <span class="tag">${ex.length}</span><div class="note">Flagged when they can read every site, use powerful permissions, or weren't installed from a web store. Remove unwanted ones from the browser's Extensions page.</div>
    ${ex.length?`<table class="tbl"><tbody>${ex.map(e=>`<tr><td><div class="fname">${esc(e.name)} <span style="color:var(--muted);font-weight:400">${esc(e.version)}</span>${e.enabled?"":'<span class="tag">disabled</span>'}</div><small>${esc(e.browser)} · ${esc(e.profile)} · ${esc(e.id)}</small></td>
      <td>${e.policy?'<span class="tag ok">installed by your organization</span>':e.unpacked?'<span class="tag bad">unpacked / developer</span>':e.from_store?'<span class="tag ok">web store</span>':'<span class="tag warn">not from a store</span>'}</td>
      <td style="max-width:260px">${e.risky.slice(0,4).map(p=>`<span class="tag warn" style="margin:0 4px 3px 0;display:inline-block">${esc(p)}</span>`).join("")}${e.risky.length>4?`<span class="tag">+${e.risky.length-4}</span>`:""}</td>
      <td><span class="tag ${RISK[e.level]}">${e.level}</span></td><td class="act"><button class="ghost mini" data-open="${esc(e.path)}">${ICO_OPEN}</button></td></tr>`).join("")}</tbody></table>`:`<div class="note">No extensions found.</div>`}</div>`;
  h+=`<div class="card"><b>Home page and search engine</b><table class="tbl"><tbody>${d.homepages.map(x=>`<tr><td><div class="fname">${esc(x.browser)} · ${esc(x.profile)}</div><small>Search: ${esc(x.search)}${x.startup.length?" · Start pages: "+esc(x.startup.join(", ")):""}</small></td><td>${x.flags.length?x.flags.map(f=>`<span class="tag warn">${esc(f)}</span>`).join(""):'<span class="tag ok">looks normal</span>'}</td></tr>`).join("")||"<tr><td>No browser profiles found.</td></tr>"}</tbody></table></div>`;
  const sus=d.startup_flags.map(i=>({name:i.name,where:i.kind+" · "+i.cmd,exe:i.exe,sig:i.signature})).concat(d.tasks.map(t=>({name:t.name,where:"Scheduled task "+t.path+" · "+t.action,exe:t.exe,sig:t.signature})));
  h+=`<div class="card"><b>Startup items and tasks running from AppData or Temp</b>${sus.length?`<table class="tbl"><tbody>${sus.map(x=>`<tr><td><div class="fname">${esc(x.name)}</div><small>${esc(x.where)}</small></td><td>${sigTag(x.sig)}</td><td class="act"><button class="ghost mini" data-open="${esc(x.exe)}">${ICO_OPEN}</button></td></tr>`).join("")}</tbody></table><div class="note">You can switch startup items off on the Startup tab.</div>`:`<div class="note" style="margin-top:6px">Nothing suspicious. Signed apps that run from AppData (like Teams or Zoom) aren't flagged.</div>`}</div>`;
  const ho=d.hosts,px=d.proxy;
  h+=`<div class="card"><b>Hosts file and proxy</b><div class="kv"><span>Hosts file</span><b>${ho.entries.length?`${ho.entries.length} custom entr${ho.entries.length>1?"ies":"y"}`:"default (no custom entries)"}</b>
     <span>Proxy</span><b>${px.enabled?esc(px.server||"on"):"off"}</b><span>Auto-config script</span><b>${esc(px.pac||"none")}</b></div>
    ${ho.entries.length?`<details><summary>Hosts entries (${ho.entries.length})</summary><ul>${ho.entries.slice(0,40).map(e=>`<li>line ${e.line}: ${esc(e.text)}</li>`).join("")}</ul></details>`:""}
    <div class="note" style="margin-top:6px">Custom hosts entries or a proxy can redirect websites. On a work PC they're often set by IT on purpose.</div></div>`;
  h+=`<div class="card"><b>Privacy: browsing data</b> <span class="tag">read-only</span><div class="note">These files hold your history, cookies (sign-ins) and autofill. The app only shows their size and never deletes them. To clear them, use the browser's own Ctrl+Shift+Delete.</div>
    <table class="tbl"><thead><tr><th>Browser profile</th><th class="num">History</th><th class="num">Cookies</th><th class="num">Form data</th><th class="num">Total</th></tr></thead><tbody>${d.privacy.map(x=>`<tr><td>${esc(x.browser)} · ${esc(x.profile)}</td><td class="num">${fmtB(x.sizes.History)}</td><td class="num">${fmtB(x.sizes.Cookies)}</td><td class="num">${fmtB(x.sizes["Form data"])}</td><td class="num">${fmtB(x.total)}</td></tr>`).join("")}</tbody></table></div>`;
  $("#protBody").innerHTML=h;
  $$("#protBody [data-open]").forEach(b=>b.onclick=()=>openLoc(b.dataset.open));
  const q=$("#qsBtn");if(q)q.onclick=()=>applyActions([{type:"defender_quickscan"}])}

/* ================= startup */
const ST={data:null,filter:"all"};
async function loadStartup(force){adminUI("#stAdmin");if(force||!ST.data){if(!ST.data)$("#stBody").innerHTML=`<div class="card"><div class="bar indet"><i></i></div><div class="ptext"><span>Reading startup items and checking signatures…</span></div></div>`;
  try{ST.data=await api("/api/startup"+(force?"?force=1":""))}catch(e){return snack(e.message,1)}}renderStartup()}
$("#stRefresh").onclick=()=>loadStartup(true);
function renderStartup(){const d=ST.data;if(!d)return;
  const F={all:()=>1,run:i=>i.kind.startsWith("Registry")||i.kind.startsWith("RunOnce"),folder:i=>i.kind==="Startup folder",task:i=>i.kind.startsWith("Scheduled"),svc:i=>i.kind.startsWith("Auto-start")};
  const items=d.items.filter(F[ST.filter]).sort((a,b)=>((b.broken&&b.enabled)-(a.broken&&a.enabled))||(b.suspicious-a.suspicious)||(b.enabled-a.enabled)||a.name.localeCompare(b.name));
  const cnt=k=>d.items.filter(F[k]).length;
  let h=`<div class="stats">${[["On at startup",d.enabled,"login and boot"],["Total items",d.total,"incl. tasks and services"],["Broken",d.broken||0,"what they start is missing"],["Suspicious",d.suspicious,"unsigned in AppData/Temp"]]
    .map(([a,b,c],i)=>`<div class="card stat"><small>${a}</small><b ${i>=2&&b?'style="color:var(--warn)"':""}>${fmtN(b)}</b><em>${c}</em></div>`).join("")}</div>
   <div class="chips" style="margin:0 0 12px">${[["all","All"],["run","Registry"],["folder","Startup folder"],["task","Scheduled tasks"],["svc","Services"]].map(([k,n])=>`<button class="chip ${ST.filter===k?"on":""}" data-f="${k}">${n} <b>${cnt(k)}</b></button>`).join("")}</div>
   <div class="card" style="padding:6px 10px"><table class="tbl"><thead><tr><th style="width:52px">On</th><th>Item</th><th>Type</th><th>Publisher</th><th>Impact</th><th></th></tr></thead><tbody>${items.map(i=>`<tr>
    <td>${i.can_toggle?`<button class="tgl ${i.enabled?"on":""}" data-t="${esc(i.id)}" title="${i.enabled?"Switch off":"Switch on"}"><span class="sw"></span></button>`:`<span class="tag ${i.enabled?"ok":""}">${i.enabled?"on":"off"}</span>`}</td>
    <td><div class="fname">${esc(i.name)}${i.broken?'<span class="tag bad">broken</span>':""}${i.suspicious?'<span class="tag bad">suspicious</span>':""}${i.needs_admin?'<span class="tag warn">needs admin</span>':""}</div><small>${esc(i.cmd)}</small>${i.broken?`<small style="color:var(--warn)">Broken: ${esc(i.broken_reason)}${i.target&&i.target!==i.exe?` (${esc(i.target)})`:""}</small>`:""}</td>
    <td><span style="font-size:12.5px">${esc(i.kind)}</span><small>${esc(i.scope==="user"?"this user":i.scope==="all users"?"all users":i.where)}</small></td>
    <td>${esc(i.publisher||"–")} ${sigTag(i.signature)}</td><td><span class="tag ${i.impact==="high"?"warn":i.impact==="medium"?"":"ok"}">${esc(i.impact)}</span></td>
    <td class="act">${i.exe&&!i.broken?`<button class="ghost mini" data-open="${esc(i.path||i.target||i.exe)}">${ICO_OPEN}</button>`:""}</td></tr>`).join("")||'<tr><td colspan="6" class="empty">Nothing here.</td></tr>'}</tbody></table>
   <div class="note" style="padding:8px">Registry and Startup-folder items switch on and off the same way Task Manager does it. Your own scheduled tasks in the Task Scheduler root can be switched too (reversible); other tasks and services are read-only here. "Broken" means the program or script it starts is missing. Impact is estimated from the program's size.</div></div>`;
  $("#stBody").innerHTML=h;
  $$("#stBody [data-f]").forEach(b=>b.onclick=()=>{ST.filter=b.dataset.f;renderStartup()});
  $$("#stBody [data-open]").forEach(b=>b.onclick=()=>openLoc(b.dataset.open));
  $$("#stBody [data-t]").forEach(b=>b.onclick=async()=>{const it=d.items.find(x=>x.id===b.dataset.t);const en=!it.enabled;
    const ok=await confirmBox({icon:"move",title:`${en?"Switch on":"Switch off"} "${it.name}" at startup?`,ok:en?"Switch on":"Switch off",
      html:`${en?"It will start again the next time you sign in.":"It won't start automatically next time you sign in. The program itself isn't removed."}<ul><li>${esc(it.cmd)}</li></ul>Reversible: flip the switch back any time.`});if(!ok)return;
    try{await post("/api/startup/toggle",{id:it.id,enable:en,confirm:"yes"});it.enabled=en;d.enabled+=en?1:-1;renderStartup();
      snackAct(`${it.name} switched ${en?"on":"off"}`,"Undo",async()=>{try{await post("/api/startup/toggle",{id:it.id,enable:!en,confirm:"yes"});it.enabled=!en;d.enabled+=en?-1:1;renderStartup();snack("Undone")}catch(e){snack(e.message,1)}})}
    catch(e){snack(e.message,1)}})}

/* ================= monitor */
const M={timer:null,ptimer:null,sort:"cpu",procs:[],q:""};
function startMon(){if(M.timer)return;tickMon();M.timer=setInterval(tickMon,1000);tickProcs();M.ptimer=setInterval(tickProcs,3000)}
function stopMon(){clearInterval(M.timer);clearInterval(M.ptimer);M.timer=M.ptimer=null}
async function tickMon(){let r;try{r=await api("/api/mon")}catch(e){return}const n=r.now||{},h=r.hist||[];
  if(!n.t){$("#monGrid").innerHTML='<div class="card empty" style="grid-column:1/-1">Starting the monitor…</div>';return}renderMon(n,h)}
function mcard(title,right,val,sub,extra){return `<div class="card mcard"><div class="mh2"><span>${title}</span><span>${right||""}</span></div><div class="val">${val}</div><div class="sub">${sub}</div>${extra||""}</div>`}
function renderMon(n,h){const H=k=>h.map(x=>x[k]);const used=n.mem_total-n.mem_avail;const g=n.gpu;const b=n.battery;const t=n.temps;
  const io=n.io_ready?"":" · starting…";
  const cores=(n.cores||[]).length?`<div class="cores" style="grid-template-columns:repeat(${Math.min(10,n.cores.length)},1fr)">${n.cores.map(c=>`<i title="${c}%"><span style="height:${c}%"></span></i>`).join("")}</div>`:"";
  const drv=(n.disks||[]).map(d=>`<span>${esc(d.root.replace(/\\$/,""))} ${pct(d.used,d.total)}% used</span><b>R ${fmtRate(d.read||0)} · W ${fmtRate(d.write||0)}</b>`).join("");
  const nets=(n.nets||[]).filter(x=>x.rx+x.tx>0).slice(0,3).map(x=>`<span title="${esc(x.name)}">${esc(x.name.slice(0,28))}</span><b>↓ ${fmtRate(x.rx)} · ↑ ${fmtRate(x.tx)}</b>`).join("");
  const cpuT=t&&t.zones&&t.zones.length?t.zones.map(z=>z.c+"°C").join(" · "):"not readable";
  $("#monGrid").innerHTML=
    mcard("CPU",`${n.ncpu} threads`,`${n.cpu.toFixed(0)}%`,`Per-core load below`,spark(H("cpu"),"#2dd4bf",100)+cores)+
    mcard("Memory",`${n.mem_pct}%`,fmtB(used),`of ${fmtB(n.mem_total)} · ${fmtB(n.mem_avail)} available`,spark(H("mem"),"#7c6cff",100)+`<div class="kv"><span>Committed</span><b>${fmtB(n.commit)} / ${fmtB(n.commit_limit)}</b></div>`)+
    mcard("Disk",'read + write',fmtRate((n.disk_read||0)+(n.disk_write||0)),`Read ${fmtRate(n.disk_read||0)} · Write ${fmtRate(n.disk_write||0)}${io}`,spark(h.map(x=>(x.rd||0)+(x.wr||0)),"#6ea8fe")+`<div class="kv">${drv}</div>`)+
    mcard("Network","down + up",fmtRate((n.net_rx||0)+(n.net_tx||0)),`↓ ${fmtRate(n.net_rx||0)} · ↑ ${fmtRate(n.net_tx||0)}${io}`,spark(h.map(x=>(x.rx||0)+(x.tx||0)),"#facc15")+`<div class="kv">${nets||"<span>No traffic</span><b></b>"}</div>`)+
    (g?mcard("GPU",esc(g.name.replace("NVIDIA GeForce ","")),g.util==null?"idle":`${g.util.toFixed(0)}%`,`VRAM ${fmtB(g.mem_used)} of ${fmtB(g.mem_total)}`,spark(H("gpu"),"#f472b6",100)+
      `<div class="kv"><span>Temperature</span><b>${g.temp==null?"–":g.temp+"°C"}</b><span>Power</span><b>${g.power==null?"–":g.power.toFixed(0)+" W"}</b><span>VRAM used</span><b>${pct(g.mem_used,g.mem_total)}%</b></div>`)
      :mcard("GPU","","–","No NVIDIA GPU data (nvidia-smi not found)",""))+
    mcard("System","",upt(n.uptime),"up since last restart",`<div class="kv"><span>Battery</span><b>${b?`${b.pct==null?"?":b.pct}% · ${b.charging?"charging":b.ac?"plugged in":"on battery"}`:"no battery"}</b>
      ${b&&b.secs_left?`<span>Time left</span><b>${upt(b.secs_left)}</b>`:""}<span>CPU temperature</span><b>${cpuT}</b><span>GPU temperature</span><b>${g&&g.temp!=null?g.temp+"°C":"–"}</b></div>${t&&t.note?`<div class="note" style="margin-top:6px;font-size:11.5px">${esc(t.note)}</div>`:""}`);
  $("#monUp").textContent="Live · "+new Date(n.t*1000).toLocaleTimeString()}
async function tickProcs(){try{M.procs=(await api("/api/procs")).items}catch(e){return}renderProcs()}
function renderProcs(){const q=M.q.toLowerCase();let l=M.procs.filter(p=>p.pid&&(!q||p.name.toLowerCase().includes(q)||String(p.pid)===q));
  l.sort({cpu:(a,b)=>b.cpu-a.cpu||b.mem-a.mem,mem:(a,b)=>b.mem-a.mem,name:(a,b)=>a.name.localeCompare(b.name)}[M.sort]);
  $$("#procSort button").forEach(b=>b.classList.toggle("on",b.dataset.s===M.sort));
  $("#procList").innerHTML=l.length?`<table class="tbl"><thead><tr><th>Name</th><th class="num">PID</th><th class="num">CPU</th><th class="num">Memory</th><th class="num">Threads</th><th></th></tr></thead><tbody>${l.slice(0,60).map(p=>`<tr>
    <td><div class="fname">${esc(p.name)}${p.critical?'<span class="tag">system</span>':""}</div></td><td class="num" style="color:var(--muted)">${p.pid}</td><td class="num">${p.cpu.toFixed(1)}%</td><td class="num">${p.mem?fmtB(p.mem):"–"}</td><td class="num" style="color:var(--muted)">${p.threads}</td>
    <td class="act"><button class="ghost mini" data-end="${p.pid}" ${p.critical?"disabled":""}>End task…</button></td></tr>`).join("")}</tbody></table>${l.length>60?`<div class="more">+ ${l.length-60} more · filter to find others</div>`:""}`
    :`<div class="empty" style="padding:20px">${M.procs.length?"No matching process.":"Reading processes…"}</div>`;
  $$("#procList [data-end]").forEach(b=>b.onclick=async()=>{const p=M.procs.find(x=>x.pid===+b.dataset.end);if(!p)return;
    const ok=await confirmBox({icon:"danger",danger:1,title:`End ${p.name}?`,ok:"End task",html:`PID ${p.pid} · ${fmtB(p.mem)} memory. Unsaved work in it will be lost. This is the same as End task in Task Manager.`});if(!ok)return;
    try{await post("/api/proc/end",{pid:p.pid,name:p.name,created:p.created,confirm:"yes"});snack(`Ended ${p.name}`);tickProcs()}catch(e){snack(e.message,1)}})}
$("#procQ").oninput=e=>{M.q=e.target.value;renderProcs()};
$$("#procSort button").forEach(b=>b.onclick=()=>{M.sort=b.dataset.s;renderProcs()});

/* ================= settings (recommendations / AI) */
async function loadSettings(){try{S.ai=await api("/api/ai")}catch(e){return snack(e.message,1)}renderAI()}
function renderAI(){const a=S.ai;$("#aiToggle").classList.toggle("on",a.enabled);$("#aiState").textContent=a.enabled?"On":"Off";
  $$("#aiProv button").forEach(b=>b.classList.toggle("on",b.dataset.p===a.provider));
  $("#aiUrl").value=a.base_url||"";$("#aiModel").value=a.model||"";$("#aiKey").value=a.key_env||"";$("#aiTimeout").value=a.timeout||45;
  const ai=a.provider==="openai";["#aiUrl","#aiModel","#aiKey","#aiTimeout","#aiTest","#aiLoadModels"].forEach(s=>$(s).disabled=!ai);
  $("#aiNote").innerHTML=(ai?`The API key itself is never stored or logged. Set it as a Windows environment variable named <b>${esc(a.key_env||"…")}</b> (${a.key_present?'<span class="tag ok">found</span>':'<span class="tag warn">not set</span>'}); the app reads it only when it asks the endpoint for suggestions. A local server (LM Studio or Ollama) needs no key. AI suggestions can only use the app's own allowlisted actions, and every one is checked by the app before it's shown.`
    :"Built-in rules run locally with no network: they look at your last Smart Scan and suggest cleanups, organizing, startup changes, scans and app updates.")+
    (a.enabled?"":` <b>Currently off:</b> nothing is computed and no network calls are made.`)}
$("#aiToggle").onclick=()=>{S.ai.enabled=!S.ai.enabled;renderAI()};
$$("#aiProv button").forEach(b=>b.onclick=()=>{S.ai.provider=b.dataset.p;renderAI()});
const aiForm=()=>({base_url:$("#aiUrl").value,model:$("#aiModel").value,key_env:$("#aiKey").value,timeout:+$("#aiTimeout").value||45});
$("#aiTest").onclick=async()=>{const o=$("#aiTestOut");o.innerHTML=`<span class="tag">testing…</span> one tiny request to ${esc($("#aiModel").value||"the model")}`;
  try{const t=await post("/api/ai/test",aiForm());
    o.innerHTML=t.ok?`<span class="tag ok">connected</span> ${fmtN(t.ms)} ms · model <b>${esc(t.model)}</b>${t.provider?` via ${esc(t.provider)}`:""} · key ${t.key_present?"found":"not set"} · timeout ${t.timeout} s`
      :`<span class="tag bad">failed</span> ${esc(t.error)} · after ${fmtN(t.ms)} ms · key ${t.key_present?"found":"not set"}`}
  catch(e){o.innerHTML=`<span class="tag bad">failed</span> ${esc(e.message)}`}};
$("#aiLoadModels").onclick=async()=>{try{const r=await post("/api/ai/models",aiForm());$("#aiModelList").innerHTML=r.items.map(m=>`<option value="${esc(m.id)}">${m.free?"free":""}</option>`).join("");
  snack(`${r.items.length} models loaded${r.items.some(m=>m.free)?` (${r.items.filter(m=>m.free).length} free)`:""}. Click the Model box to pick one.`)}catch(e){snack(e.message,1)}};
$("#aiSave").onclick=async()=>{try{S.ai=await post("/api/ai/settings",{enabled:S.ai.enabled,provider:S.ai.provider,...aiForm()});
  renderAI();snack(`Saved. Recommendations are ${S.ai.enabled?"ON":"OFF"}.`)}catch(e){snack(e.message,1)}};

/* ================= saved organize rules */
async function loadRules(){try{S.rules=(await api("/api/rules")).items}catch(e){S.rules=[]}renderRules()}
function renderRules(){const el=$("#orgRules");if(!el)return;
  el.innerHTML=`<span style="color:var(--muted);font-size:12.5px">Saved rules:</span>${(S.rules||[]).map((r,i)=>`<span class="rchip" title="${esc(r.folder)} · by ${r.rule}">${esc(r.name)}<button data-run="${i}" title="Preview this rule">▶</button><button data-del="${i}" title="Delete rule">×</button></span>`).join("")||'<span style="color:var(--muted);font-size:12.5px">none yet</span>'}
    <span style="flex:1"></span><input id="ruleName" placeholder="Name this setup" maxlength="60"><button class="ghost mini" id="ruleSave">Save as rule</button>`;
  $$("#orgRules [data-run]").forEach(b=>b.onclick=()=>{const r=S.rules[+b.dataset.run];$("#orgPath").value=r.folder;setRule(r.rule);S.skipLinks=r.skip_links;$("#linkToggle").classList.toggle("on",S.skipLinks);orgChips();preview()});
  $$("#orgRules [data-del]").forEach(b=>b.onclick=async()=>{const r=S.rules[+b.dataset.del];try{S.rules=(await post("/api/rules/delete",{name:r.name})).items;renderRules()}catch(e){snack(e.message,1)}});
  $("#ruleSave").onclick=async()=>{const name=$("#ruleName").value.trim();if(!name)return snack("Give the rule a name",1);
    try{S.rules=(await post("/api/rules/save",{name,folder:$("#orgPath").value.trim(),rule:S.rule,skip_links:S.skipLinks})).items;renderRules();snack(`Saved rule "${name}". Click ▶ to preview it any time.`)}catch(e){snack(e.message,1)}}}

/* ================= registry backups (activity) */
async function loadRegBk(){let r;try{r=await api("/api/reg/backups")}catch(e){return}
  $("#regCard").innerHTML=`<div class="row"><b style="flex:1">Registry backups</b><span style="color:var(--muted);font-size:12px">${esc(r.dir)}</span></div>`+
    (r.items.length?`<table class="tbl"><tbody>${r.items.slice(0,30).map(x=>`<tr><td><div class="fname">${esc(x.key)}</div><small>${esc(x.file)} · deleted ${esc(x.time)}${x.restored?" · restored "+esc(x.restored):""}</small></td>
      <td class="act"><button class="ghost mini" data-rest="${esc(x.file)}">Restore…</button></td></tr>`).join("")}</tbody></table>`
      :`<div class="note" style="margin-top:6px">No registry keys have been removed. When you remove leftover keys, each one is exported here first so you can restore it.</div>`);
  $$("#regCard [data-rest]").forEach(b=>b.onclick=async()=>{const f=b.dataset.rest,x=r.items.find(i=>i.file===f);
    const ok=await confirmBox({icon:"move",title:"Restore this registry key?",ok:"Restore",html:`<b>${esc(x.key)}</b> is imported back from <ul><li>${esc(f)}</li></ul>`});if(!ok)return;
    try{await post("/api/reg/restore",{file:f,confirm:"yes"});snack("Registry key restored");loadRegBk()}catch(e){snack(e.message,1)}})}

/* ---------------- keys */
document.addEventListener("keydown",e=>{const typing=/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
  const modalOpen=!$("#modal").hidden;
  if(e.key==="Escape"){if(modalOpen)return closeModal(false);if(!$("#kb").hidden)return kb(0);if(S.scanJob)return post("/api/job/cancel",{id:S.scanJob});if(D.job)return post("/api/job/cancel",{id:D.job});if(typing)document.activeElement.blur();return}
  if(modalOpen){if(e.key==="Enter"&&!$("#mYes").disabled){e.preventDefault();closeModal(true)}return}
  if(e.key==="F5"||((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="r")){e.preventDefault();
    if(S.view==="scan")startScan();else if(S.view==="cleanup"){S.cats=null;measure()}else if(S.view==="organize")preview();else if(S.view==="dashboard")smartScan();else if(S.view==="apps")loadApps(true);else if(S.view==="protection")runProt();else if(S.view==="startup")loadStartup(true);else if(S.view==="monitor")tickProcs();else if(S.view==="activity"){loadLog();loadRegBk()}return}
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="z"&&!typing&&S.view==="organize"){e.preventDefault();undoOrg();return}
  if(typing||e.ctrlKey||e.altKey||e.metaKey)return;
  if(e.key==="?"){kb($("#kb").hidden);return}
  if(!$("#kb").hidden)return;
  if(e.shiftKey&&/^Digit[1-4]$/.test(e.code)&&S.view==="scan"&&S.st.scan){S.sub=["map","large","dups","old"][+e.code.slice(5)-1];renderScan();return}
  if(/^[1-9]$/.test(e.key)){show(VIEWS[+e.key-1]);return}
  if(e.key===","){show("settings");return}
  if(e.key==="/"){e.preventDefault();if(S.view==="apps"&&A.tab==="programs"&&$("#appQ")){$("#appQ").focus();return}if(S.view==="monitor"){$("#procQ").focus();return}
    const i=S.view==="organize"?$("#orgPath"):$("#scanPath");show(S.view==="organize"?"organize":"scan");i.focus();i.select();return}
  if(e.key==="Delete"&&S.view==="scan"&&S.sel.size){recycleSel();return}
  if(e.key==="Backspace"&&S.view==="scan"&&S.sub==="map"&&S.dir&&S.dir.crumbs.length>1){drill(S.dir.crumbs[S.dir.crumbs.length-2].path)}});

/* ---------------- boot */
setInterval(()=>fetch("/api/ping").catch(()=>{}),20000);
(async()=>{try{S.st=await api("/api/state")}catch(e){return snack("Can't reach the app server",1)}
  const st=S.st;renderDrives();$("#scanPath").value=st.settings.last_scan||st.home;scanChips();
  $("#orgPath").value=st.downloads;S.skipLinks=st.settings.skip_links;$("#linkToggle").classList.toggle("on",S.skipLinks);setRule(st.settings.rule||"type");orgChips();
  if(st.cats){S.cats=st.cats;S.cats.cats.forEach(c=>{if(c.default&&!c.running&&c.size)S.catSel.add(c.id)});renderCats()}
  $("#admBadge").textContent=st.admin?"admin":"";$("#admBadge").className="adm"+(st.admin?" on":"");$("#setBtn").onclick=()=>show("settings");
  const h=location.hash.slice(1);show(h==="shortcuts"?"dashboard":h||"dashboard");if(h==="shortcuts")kb(1);
  if(st.jobs&&st.jobs.scan)watchScan(st.jobs.scan.id);
  if(st.scan)await loadScan();else renderScan();renderUndo();
  const sub=new URLSearchParams(location.search).get("sub");if(sub&&st.scan){S.sub=sub;renderScan()}
  if(location.search.includes("org=1"))preview()})();
</script>
</body></html>
"""

if __name__ == "__main__":
    main()
