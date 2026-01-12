#!/usr/bin/env python3
import os
import subprocess
import time

# ===== ABSOLUTE ROOT =====
ROOT = "/home/user/Desktop/ReForge"
GHIDRA = os.path.join(ROOT, "ghidra_11.4.2_PUBLIC")
SCRIPTS = os.path.join(ROOT, "scripts")
BINARIES = os.path.join(ROOT, "binaries")
OUTROOT = os.path.join(ROOT, "results")

os.makedirs(OUTROOT, exist_ok=True)

print("[*] Starting analysis with AI normalization")
print("[*] Make sure Ollama is running: ollama serve")
start = time.time()

for binname in os.listdir(BINARIES):
    binpath = os.path.join(BINARIES, binname)
    if not os.path.isfile(binpath):
        continue
    
    outdir = os.path.join(OUTROOT, binname)
    os.makedirs(outdir, exist_ok=True)
    
    print(f"[*] Analyzing {binname}")
    
    subprocess.run([
        os.path.join(GHIDRA, "support/analyzeHeadless"),
        outdir,                         # headless project folder
        f"{binname}_proj",               # project name
        "-import", binpath,
        "-scriptPath", SCRIPTS,          # folder containing Ghidra Python scripts
        "-preScript", "EnableEffectiveDecompiler.py",
        "-postScript", "analyzer.py",
        os.path.join(outdir, "arm32_gadgets.txt"),
        os.path.join(outdir, "decompiled.c"),
        os.path.join(outdir, "xrefs.json"),
        "--use-ai"                       # Enable AI normalization
    ], check=True)

elapsed = int(time.time() - start)
print(f"[*] Done in {elapsed} seconds")
