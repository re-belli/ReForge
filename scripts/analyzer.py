#!/usr/bin/env python2

#@author re-belli
#@category 
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import * 
from ghidra.program.model.address import *
from ghidra.app.util import Option
from ghidra.util.task import TaskMonitor
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from java.io import File
from ghidra.app.util.exporter import CppExporter
from re import search
import json
import urllib2
import time
import codecs

import __main__ as ghidra_app

IMPORT_SINKS = [ "recv", "recvfrom", "recvmsg", "read", "readv", "fgets", "fread", "strcpy",
     "strncpy", "memcpy", "memmove", "sprintf", "snprintf", "sscanf" ]

NORMALIZATION_PROMPT = """You are normalizing decompiled C code produced by a reverse engineering tool.
Your task is to output VALID, COMPILABLE C code while preserving the original semantics exactly.

STRICT RULES (DO NOT VIOLATE):
- Do NOT add logic
- Do NOT remove logic
- Do NOT change control flow
- Do NOT rename the function
- Do NOT invent helper functions
- Do NOT inline or refactor code
- Do NOT introduce macros
- Do NOT add comments
- Do NOT add explanations
- Do NOT add assertions or checks
- Do NOT simplify expressions

TYPE HANDLING RULES:
- Replace unknown types with `void *`
- Replace unknown structs with opaque typedefs
- Preserve pointer semantics exactly
- Add explicit casts ONLY when required for compilation
- Do NOT guess struct fields
- Do NOT invent enums or constants

OUTPUT RULES:
- Output ONLY valid C code
- Output ONLY the function body
- No headers
- No macros
- No comments
- No explanations
- No markdown

The result MUST be suitable for `gcc -fsyntax-only`.

Function to normalize:

{body}"""


class Analyzer:

    def __init__(self, program=None, timeout=None):
        self.program = program or ghidra_app.currentProgram
        # Initialize decompiler
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(program or ghidra_app.currentProgram)
        self._options = DecompileOptions()
        self._tool = state.getTool()
        self._timeout = timeout

    def set_up_decompiler(self):
        # configure decompiler options
        self._options.setEliminateUnreachable(True)
        self._decompiler.setOptions(self._options)
        self._decompiler.toggleCCode(True)
        self._decompiler.toggleSyntaxTree(True)
        self._decompiler.setSimplificationStyle("decompile")
        return self._decompiler

    def get_all_functions(self):
        st = ghidra_app.currentProgram.getSymbolTable()
        si = st.getSymbolIterator()
        symbol_dict = {}
        funcs = []
        while si.hasNext():
            s = si.next()
            if s.getSymbolType() == SymbolType.FUNCTION and not s.isExternal() and s.getName() not in symbol_dict:
                symbol_dict[s.getName()] = s.getAddress()
        for address in symbol_dict.values():
            func = ghidra_app.currentProgram.getFunctionManager().getFunctionAt(address)
            funcs.append(func)
        return funcs

    def decompile_func(self, func):
        self._decompiler = self.set_up_decompiler()
        decomp_results = self._decompiler.decompileFunction(func, 0, self._timeout)
        if decomp_results and decomp_results.decompileCompleted():
            return decomp_results.getDecompiledFunction().getC()
        return ""

    def clean_with_ollama(self, body, func_name):
        """
        Send decompiled code to local Ollama for normalization
        """
        try:
            prompt = NORMALIZATION_PROMPT.format(body=body)
            
            payload = json.dumps({
                "model": "deepseek-coder:6.7b",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 4096
                }
            })
            
            req = urllib2.Request(
                'http://localhost:11434/api/generate',
                data=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            response = urllib2.urlopen(req, timeout=60)
            result = json.loads(response.read())
            
            cleaned = result.get('response', '').strip()
            
            # Basic validation - check if we got something back
            if cleaned and len(cleaned) > 10:
                print("[+] Cleaned function: {}".format(func_name))
                return cleaned
            else:
                print("[!] AI returned empty response for {}, using original".format(func_name))
                return body
                
        except urllib2.URLError as e:
            print("[!] Cannot connect to Ollama for {}: {}".format(func_name, str(e)))
            print("[!] Make sure Ollama is running: ollama serve")
            return body
        except Exception as e:
            print("[!] Error cleaning {}: {}".format(func_name, str(e)))
            return body

    def decompile(self, output_path):
        """
        Decompiles functions, writing incrementally to file
        """
        with codecs.open(output_path, "w", encoding="utf-8") as outfile:
            for func in self.get_all_functions():
                if not func.isThunk():
                    dec_func = self.decompile_func(func)
                    if dec_func:
                        outfile.write(dec_func)
                        outfile.flush()

    def decompile_with_ai(self, output_path):
        """
        Decompiles and AI-cleans functions, writing incrementally to file
        """
        funcs = self.get_all_functions()
        total = len([f for f in funcs if not f.isThunk()])
        current = 0
        
        print("[*] Processing {} functions with AI normalization".format(total))
        
        with codecs.open(output_path, "w", encoding="utf-8") as outfile:
            for func in funcs:
                if not func.isThunk():
                    current += 1
                    func_name = func.getName()
                    print("[*] [{}/{}] Processing: {}".format(current, total, func_name))
                    
                    dec_func = self.decompile_func(func)
                    if dec_func:
                        # Clean with AI
                        cleaned = self.clean_with_ollama(dec_func, func_name)
                        # Write immediately
                        outfile.write(cleaned)
                        outfile.flush()  # Force write to disk
                        time.sleep(0.1)

    def list_cross_references(self, dst_func, output_path=None):
        dst_name = dst_func.getName()
        dst_addr = dst_func.getEntryPoint()
        references = getReferencesTo(dst_addr)
        seen_funcs = set()
        matches = []

        for xref in references:
            if not xref.getReferenceType().isCall():
                continue

            call_addr = xref.getFromAddress()
            src_func = getFunctionContaining(call_addr)
            if src_func is None or src_func.isThunk():
                continue

            entry = src_func.getEntryPoint()
            if entry in seen_funcs:
                continue
            seen_funcs.add(entry)

            decompiled = self.decompile_func(src_func)
            for line in decompiled.splitlines():
                if search(r"\b{}\b".format(dst_name), line):
                    matches.append({
                        "sink": dst_name,
                        "caller": src_func.getName(),
                        "call_addr": str(call_addr),
                        "line": line.strip()
                    })
                    break

        return matches

    def analyze_imports(self):
        st = self.program.getSymbolTable()
        si = st.getSymbolIterator()
        targets = []

        while si.hasNext():
            s = si.next()
            if s.getSymbolType() == SymbolType.FUNCTION and s.getName() in IMPORT_SINKS:
                f = self.program.getFunctionManager().getFunctionAt(s.getAddress())
                if f:
                    targets.append(f)

        all_xrefs = []
        for f in targets:
            all_xrefs.extend(self.list_cross_references(f))
        return all_xrefs


# ============================================================================
# ARM32 ROP Gadget Finder
# ============================================================================

MAX_GADGET_LEN = 6

def is_control_flow_end(inst):
    if inst is None:
        return False
    mnem = inst.getMnemonicString().upper()
    if mnem in ["BLX", "BX"]:
        return True
    if mnem == "POP" and "pc" in inst.toString().lower():
        return True
    if mnem.startswith("LDM") and "pc" in inst.toString().lower():
        return True
    return False

def is_add_two_regs(inst):
    if inst is None:
        return False
    if inst.getMnemonicString().upper() != "ADD":
        return False
    num_ops = inst.getNumOperands()
    if num_ops != 3:
        return False
    ops = [str(inst.getDefaultOperandRepresentation(i)) for i in range(num_ops)]
    if not all(o.lower().startswith("r") or o.lower() in ["fp", "ip", "sp", "lr"] for o in ops):
        return False
    return True

def is_ldr_deref(inst):
    if inst is None:
        return False
    mnem = inst.getMnemonicString().upper()
    if not mnem.startswith("LDR"):
        return False
    num_ops = inst.getNumOperands()
    if num_ops != 2:
        return False
    ops = [str(inst.getDefaultOperandRepresentation(i)) for i in range(num_ops)]
    if "[" in ops[1] and "]" in ops[1]:
        return True
    return False

def is_str_store(inst):
    if inst is None:
        return False
    mnem = inst.getMnemonicString().upper()
    if not mnem.startswith("STR"):
        return False
    num_ops = inst.getNumOperands()
    if num_ops != 2:
        return False
    ops = [str(inst.getDefaultOperandRepresentation(i)) for i in range(num_ops)]
    if "[" in ops[1] and "]" in ops[1]:
        return True
    return False

def collect_gadget_from(end_inst):
    gadget = [end_inst]
    cur = end_inst
    for _ in range(MAX_GADGET_LEN - 1):
        prev = cur.getPrevious()
        if prev is None:
            break
        if prev.getFallFrom() is None and prev.getFlowType().isCall():
            break
        gadget.insert(0, prev)
        cur = prev
    return gadget

def find_arm32_rop_gadgets(output_path):
    print("[*] Scanning for ARM32 GOT-style gadgets (ADD / LDR [reg, imm] / STR [reg, imm])")
    
    listing = ghidra_app.currentProgram.getListing()
    code_units = listing.getInstructions(True)
    count_add = count_ldr = count_str = 0
    
    gadget_output = []
    gadget_output.append('\n\n')
    gadget_output.append('=' * 80 + '\n')
    gadget_output.append('ARM32 ROP GADGETS\n')
    gadget_output.append('=' * 80 + '\n\n')

    while code_units.hasNext() and not monitor.isCancelled():
        inst = code_units.next()
        if not is_control_flow_end(inst):
            continue

        gadget = collect_gadget_from(inst)

        has_add = any(is_add_two_regs(i) for i in gadget)
        has_ldr = any(is_ldr_deref(i) for i in gadget)
        has_str = any(is_str_store(i) for i in gadget)

        if has_add:
            count_add += 1
            start_addr = gadget[0].getAddress()
            gadget_output.append("=== ADD (reg+reg) gadget at {} ===\n".format(start_addr))
            for inst_item in gadget:
                gadget_output.append("  {}: {}\n".format(inst_item.getAddress(), inst_item))
            gadget_output.append("\n")
            
        if has_ldr:
            count_ldr += 1
            start_addr = gadget[0].getAddress()
            gadget_output.append("=== LDR [reg, imm] (deref) gadget at {} ===\n".format(start_addr))
            for inst_item in gadget:
                gadget_output.append("  {}: {}\n".format(inst_item.getAddress(), inst_item))
            gadget_output.append("\n")
            
        if has_str:
            count_str += 1
            start_addr = gadget[0].getAddress()
            gadget_output.append("=== STR [reg, imm] (write) gadget at {} ===\n".format(start_addr))
            for inst_item in gadget:
                gadget_output.append("  {}: {}\n".format(inst_item.getAddress(), inst_item))
            gadget_output.append("\n")

    gadget_output.append("\n[*] ARM32 ROP Gadget Summary:\n")
    gadget_output.append("    ADD gadgets : {}\n".format(count_add))
    gadget_output.append("    LDR gadgets : {}\n".format(count_ldr))
    gadget_output.append("    STR gadgets : {}\n".format(count_str))
    gadget_output.append('\n' + '=' * 80 + '\n\n')
    
    with open(output_path, 'w') as f:
        f.write(''.join(gadget_output))

    print("[*] Done scanning ARM32 ROP gadgets.")
    print("    ADD gadgets : {}".format(count_add))
    print("    LDR gadgets : {}".format(count_ldr))
    print("    STR gadgets : {}".format(count_str))


def run():
    args = ghidra_app.getScriptArgs()
    if len(args) < 3:
        print("Usage: analyzer.py <arm32_gadgets.txt> <decompiled.c> <xrefs.json> [--use-ai]")
        return

    gadgets_path = args[0]
    decompiled_path = args[1]
    xrefs_path = args[2]
    
    # Check for --use-ai flag
    use_ai = '--use-ai' in args
    
    if use_ai:
        print("[*] AI normalization enabled")
        print("[*] Make sure Ollama is running: ollama serve")
    else:
        print("[!] AI normalization DISABLED. Use --use-ai flag to enable.")

    # Check if binary is ARM32
    is_arm32 = (str(ghidra_app.currentProgram.language.processor) == "ARM" 
                and ghidra_app.currentProgram.language.languageDescription.size == 32)

    if is_arm32:
        print("[*] Detected ARM32 binary - ROP gadget finder will be enabled")
    else:
        print("[*] Not an ARM32 binary - skipping ROP gadget finder")

    a = Analyzer()
    
    xrefs = a.analyze_imports()

    # Save xrefs JSON
    with codecs.open(xrefs_path, "w", encoding="utf-8") as f:
        json.dump(xrefs, f, indent=2)
        print('[*] Saving xrefs to -> {}'.format(xrefs_path))

    # Run ARM32 ROP gadget finder if applicable
    if is_arm32:
        find_arm32_rop_gadgets(gadgets_path)
        print('[*] ARM32 ROP gadgets saved to -> {}'.format(gadgets_path))


     # Decompile - with or without AI (now writes directly to file)
    print('[*] Saving decompilation to -> {}'.format(decompiled_path))
    if use_ai:
        a.decompile_with_ai(decompiled_path)
    else:
        a.decompile(decompiled_path)

    print("[+] Analysis complete")

if __name__ == "__main__":
    run()
