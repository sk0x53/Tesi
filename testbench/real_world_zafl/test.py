import difflib, hashlib, math, os, random, shlex, shutil, signal, stat, struct, subprocess, sys, time
from pathlib import Path

TOOLS = ("readelf", "sfconvert", "bsdtar")
T0 = 1_700_000_000
WORK = Path("test_result").resolve()
ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8", "TZ": "UTC"}



def case(name, argv, inputs=None, stdin=None, outs=(), trees=()):
    """inputs: nome_relativo -> bytes | Path (symlink) | funzione(dest). outs: file da hashare. trees: dir da confrontare."""
    return dict(name=name, argv=argv, inputs=inputs or {}, stdin=stdin, outs=outs, trees=trees)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest() if Path(p).is_file() else "<assente>"


def digest(root):
    """Descrizione testuale di un albero di file (tipo, permessi, dimensione, hash, link, mtime se 'vecchio')."""
    lines, now = [], time.time()
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for n in sorted(dirs + files):
            p = Path(d) / n
            st, rel = p.lstat(), p.relative_to(root).as_posix()
            if stat.S_ISLNK(st.st_mode):
                lines.append(f"{rel} L {os.readlink(p)}")
            elif stat.S_ISDIR(st.st_mode):
                lines.append(f"{rel} D {stat.S_IMODE(st.st_mode):o}")
            else:
                mt = "now" if st.st_mtime > now - 3 * 86400 else int(st.st_mtime)
                lines.append(f"{rel} F {stat.S_IMODE(st.st_mode):o} {st.st_size} {mt} {st.st_nlink} {sha(p)}")
    return "\n".join(lines)


def run_side(binary, tool, c, sb):
    sb.mkdir(parents=True)
    for n, src in c["inputs"].items():
        p = sb / n
        if callable(src):
            src(p)
        elif isinstance(src, bytes):
            p.write_bytes(src)
        else:
            os.symlink(Path(src).resolve(), p)
    for d in c["trees"]:
        (sb / d).mkdir(exist_ok=True)
    try: 
        r = subprocess.run([tool] + c["argv"], executable=str(binary), cwd=sb, env=ENV, capture_output=True,
                           input=c["stdin"] or b"", timeout=30)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = "timeout", b"", b""
    return dict(rc=rc, out=out, err=err, files=[sha(sb / f) for f in c["outs"]],
                trees=["\n" + digest(sb / d) for d in c["trees"]])


def rc_str(rc):
    if isinstance(rc, int) and rc < 0:
        return f"{signal.Signals(-rc).name}" if -rc in [s.value for s in signal.Signals] else f"segnale {-rc}"
    return str(rc)


def short_diff(x, y, n=6):
    x, y = (s.decode("utf-8", "replace") if isinstance(s, bytes) else s for s in (x, y))
    d = [l for l in difflib.unified_diff(x.splitlines(), y.splitlines(), "orig", "instr", lineterm="", n=0)
         if not l.startswith(("---", "+++", "@@"))]
    return "\n".join("        " + l[:110] for l in d[:n]) or "        (stesse righe: differenza a livello di byte)"


def differences(a, b):
    d = {}
    if a["rc"] != b["rc"]:
        d["exit code"] = f"originale={rc_str(a['rc'])}  strumentato={rc_str(b['rc'])}"
    for k, label in (("out", "stdout"), ("err", "stderr")):
        if a[k] != b[k]:
            d[label] = "\n" + short_diff(a[k], b[k])
    if a["files"] != b["files"]:
        d["file prodotto"] = "contenuto diverso"
    if a["trees"] != b["trees"]:
        d["file estratti"] = "\n" + short_diff("\n".join(a["trees"]), "\n".join(b["trees"]))
    return d


def test_tool(tool, orig, instr, cases):
    ok = bad = skipped = 0
    for i, c in enumerate(cases):
        cdir = WORK / tool / f"{i:03d}"
        a, b = run_side(orig, tool, c, cdir / "orig"), run_side(instr, tool, c, cdir / "instr")
        d = differences(a, b)
        if d and set(d) <= set(differences(a, run_side(orig, tool, c, cdir / "orig2"))):
            skipped, d = skipped + 1, {} 
        if d:
            bad += 1
            if bad <= 8:
                print(f"  FAIL [{i:03d}] {c['name']}\n        comando: {tool} {' '.join(shlex.quote(x) for x in c['argv'])}"
                      f"\n        cartella: {cdir}")
                for k, v in d.items():
                    print(f"      - {k}: {v}")
            elif bad == 9:
                print("  ... altri fallimenti non mostrati (cartelle dei casi in quicktest_work)")
        else:
            ok += 1
            shutil.rmtree(cdir, ignore_errors=True)
    return ok, bad, skipped

C_SRC = """#include <stdio.h>
__thread int t = 3; int g = 42; const char *m = "hi";
int f(int n){ return n < 2 ? n : f(n-1) + f(n-2); }
int main(int c, char **v){ switch (c % 3) { case 0: puts("a"); break; case 1: puts("b"); break; default: puts("c"); }
  printf("%d %d %s\\n", f(10), g + t, m); return c % 2; }
"""
READELF_OPTS = (["-h"], ["-l", "-W"], ["-S", "-W"], ["-s", "-W"], ["-r", "-W"], ["-d"], ["-n"], ["-a", "-W"])


def cases_readelf(work, orig):
    work.mkdir(parents=True)
    (work / "t.c").write_text(C_SRC)
    files, gcc = {}, shutil.which("gcc") or shutil.which("cc")
    for name, flags in (("pie_g", ["-g"]), ("stripped", ["-O2", "-s"]), ("obj", ["-c", "-g"]), ("so", ["-shared", "-fPIC"])):
        if gcc and subprocess.run([gcc, *flags, "t.c", "-o", name], cwd=work, capture_output=True).returncode == 0:
            files[name] = work / name
    for t in ("ls", "cat"):
        if shutil.which(t):
            files["sys_" + t] = Path(shutil.which(t)).resolve()
    cs = [case(f"{n} {' '.join(o)}", o + ["f"], {"f": p}) for n, p in files.items() for o in READELF_OPTS]
    if files:
        data = next(iter(files.values())).read_bytes()
        bad = {"ELF troncato": data[:900], "header ELF rotto": data[:16] + bytes(48) + data[64:], "non e' un ELF": b"ciao\n" * 50}
        cs += [case(f"{n}: -a -W", ["-a", "-W", "f"], {"f": b}) for n, b in bad.items()]
    return cs + [case("file mancante", ["-h", "nofile"]), case("nessun argomento", []), case("--version", ["--version"])]


def pcm(bits, ch, endian, n=2200, rate=22050): 
    out, m = bytearray(), (1 << (bits - 1)) - 1
    for i in range(n):
        for c in range(ch):
            q = int(0.6 * m * math.sin(2 * math.pi * (440 + 110 * c) * i / rate))
            u = bits == 8 and endian == "little"
            out += (q + 128 if u else q).to_bytes(bits // 8, endian, signed=not u)
    return bytes(out)


def wav(bits, ch, rate=22050):
    d = pcm(bits, ch, "little")
    body = b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, ch, rate, rate * ch * bits // 8, ch * bits // 8, bits)
    body += b"data" + struct.pack("<I", len(d)) + d
    return b"RIFF" + struct.pack("<I", len(body)) + body


def aiff(bits, ch, rate=22050):
    d, (m, e) = pcm(bits, ch, "big"), math.frexp(rate)
    body = b"AIFFCOMM" + struct.pack(">IhIh", 18, ch, 2200, bits) + struct.pack(">HQ", e + 16382, int(m * (1 << 64)))
    body += b"SSND" + struct.pack(">III", len(d) + 8, 0, 0) + d
    return b"FORM" + struct.pack(">I", len(body)) + body


def au(bits, ch, rate=22050):
    d = pcm(bits, ch, "big")
    return b".snd" + struct.pack(">IIIII", 24, len(d), {8: 2, 16: 3, 24: 4}[bits], rate, ch) + d


SF_CONVS = ([], ["format", "aiff"], ["format", "wave"], ["format", "next"], ["format", "aifc"],
            ["format", "wave", "integer", "16", "2scomp"], ["format", "aiff", "channels", "1"],
            ["format", "next", "compression", "ulaw"])


def cases_sfconvert(work, orig):
    srcs = {"wav16_stereo.wav": wav(16, 2), "wav8_mono.wav": wav(8, 1), "wav24_stereo.wav": wav(24, 2),
            "aiff16_stereo.aiff": aiff(16, 2), "aiff8_mono.aiff": aiff(8, 1), "au16_mono.au": au(16, 1)}
    cs = []
    for n, data in srcs.items():
        for cv in SF_CONVS:
            inn, out = "in." + n.rsplit(".", 1)[1], "out." + (cv[1] if cv else "dat")
            cs.append(case(f"{n} -> {' '.join(cv) or 'senza opzioni'}", [inn, out] + cv, {inn: data}, outs=(out,)))
    w = srcs["wav16_stereo.wav"]
    return cs + [case("wav troncato", ["in.wav", "out.wav", "format", "wave"], {"in.wav": w[:30]}, outs=("out.wav",)),
                 case("file non audio", ["in.wav", "out.wav"], {"in.wav": b"testo\n" * 20}, outs=("out.wav",)),
                 case("input mancante", ["nofile.wav", "out.wav"]), case("nessun argomento", [])]


def fixture(dest):
    """Albero di prova deterministico: file vuoto/testo/binario, dir annidate, nome unicode e lungo, symlink, hardlink."""
    rng, dest = random.Random(1), Path(dest)
    for n, data in {"hello.txt": b"hello\n", "empty.txt": b"", "binary.bin": bytes(rng.randrange(256) for _ in range(5000)),
                    "dir/a.txt": b"a\n" * 100, "dir/sub/b.txt": b"b\n" * 500, "unicode_\u00fc\u00ef.txt": "\u00fc\n".encode(),
                    "long/" + "d" * 60 + "/" + "e" * 60 + "/f.txt": b"long\n", "run.sh": b"#!/bin/sh\n"}.items():
        (dest / n).parent.mkdir(parents=True, exist_ok=True)
        (dest / n).write_bytes(data)
    os.chmod(dest / "run.sh", 0o755)
    (dest / "emptydir").mkdir()
    os.symlink("dir/a.txt", dest / "link")
    os.symlink("missing", dest / "dangling")
    os.link(dest / "hello.txt", dest / "hard.txt")
    for i, p in enumerate(sorted(dest.rglob("*"), key=lambda p: -len(p.parts)) + [dest]):  # figli prima dei padri
        os.utime(p, (T0 + i * 60,) * 2, follow_symlinks=False)


def cases_bsdtar(work, orig):
    work.mkdir(parents=True)
    fixture(work / "tree")
    arcs = {}
    for name, fmt, flt in (("ustar.tar", "ustar", []), ("pax.tar.gz", "pax", ["-z"]), ("gnutar.tar.xz", "gnutar", ["-J"]),
                           ("zip.zip", "zip", []), ("7zip.7z", "7zip", [])):
        if subprocess.run([str(orig), "--format", fmt, *flt, "-cf", name, "tree"], cwd=work, env=ENV,
                          capture_output=True).returncode == 0:
            arcs[name] = work / name
    cs = []
    for fmt, flt, ext in (("ustar", [], "tar"), ("ustar", ["-z"], "tgz"), ("ustar", ["-j"], "tbz"), ("gnutar", ["-J"], "txz"),
                          ("ustar", ["--zstd"], "tzst")):  # creazione (pax/7zip/zip salvano il ctime: byte diversi a ogni run)
        cs.append(case(f"crea {fmt} {' '.join(flt)}", ["--format", fmt, *flt, *(["--options", "gzip:!timestamp"] * ("-z" in flt)), "-cf", "out." + ext, "tree"],
                       {"tree": fixture}, outs=("out." + ext,)))
    cs.append(case("crea su stdout", ["--format", "ustar", "-cf", "-", "tree"], {"tree": fixture}))
    for n, p in arcs.items():
        for lab, av, tree in (("lista", ["-tf", "a"], 0), ("lista dettagliata", ["-tvf", "a"], 0),
                              ("estrai", ["-xf", "a", "-C", "out"], 1), ("estrai su stdout", ["-xOf", "a"], 0)):
            cs.append(case(f"{n}: {lab}", av, {"a": p}, trees=("out",) if tree else ()))
    if "ustar.tar" in arcs:
        cs.append(case("estrai da stdin", ["-xf", "-", "-C", "out"], stdin=arcs["ustar.tar"].read_bytes(), trees=("out",)))
    for n in ("pax.tar.gz", "zip.zip"):
        if n in arcs:
            cut = arcs[n].read_bytes()
            cut = cut[:len(cut) * 6 // 10]
            cs += [case(f"{n} troncato: lista", ["-tf", "a"], {"a": cut}),
                   case(f"{n} troncato: estrai", ["-xf", "a", "-C", "out"], {"a": cut}, trees=("out",))]
    return cs + [case("archivio mancante", ["-tf", "nofile.tar"]), case("--version", ["--version"]), case("nessun argomento", [])]



BUILD = {"readelf": cases_readelf, "sfconvert": cases_sfconvert, "bsdtar": cases_bsdtar}



def main():
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir()
    failures = 0

    for binary in ["bsdtar","readelf","sfconvert"]:

        ok, bad, skipped = test_tool(
            binary, 
            Path(Path.cwd() / binary / f"{binary}"),
            Path(Path.cwd() / binary / f"{binary}.mine"),   
            BUILD[binary](WORK / "_corpus" / binary, 
                          Path(Path.cwd() / binary / f"{binary}")))

        
        print(f"{binary:10s} {'OK  ' if not bad else 'FAIL'} {ok}/{ok + bad} casi uguali" +
              (f", {bad} DIVERSI" if bad else "") + (f", {skipped} ignorati (originale nondeterministico)" if skipped else "") + "\n")
        failures += bad
    if not failures:
        shutil.rmtree(WORK, ignore_errors=True)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
