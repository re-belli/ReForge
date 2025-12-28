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

import __main__ as ghidra_app


class Analyzer:

    def __init__(self, program=None, timeout=None):
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

    def unoverflow(self, x):
        return (abs(x) ^ 0xff) + 1

    def to_hex(self, integer):
        return '{:02x}'.format(integer)

    def get_function_signature(self, func):
        return func.getPrototypeString(False, True) + '\n'

    def get_instructions(self, func):
        instructions = ''
        func_addr = func.getEntryPoint()
        insts = list(ghidra_app.currentProgram.getListing().getInstructions(func_addr, True))

        # Determine the max byte length of instructions in this function
        max_bytes = max([len(inst.getBytes()) for inst in insts]) if insts else 0
        byte_col_width = max_bytes * 3  # 2 hex digits + 1 space per byte

        for inst in insts:
            # Stop if instruction is outside this function
            if ghidra_app.getFunctionContaining(inst.getAddress()) != func:
                break

            # Convert instruction bytes to hex
            byte_str = ' '.join(
                [self.to_hex(b) if b >= 0 else self.to_hex(self.unoverflow(b)) for b in inst.getBytes()]
            ).ljust(byte_col_width)

            # Format: address column, byte column, instruction text
            instructions += '{addr:<16} {byte} {inst}\n'.format(
                addr=inst.getAddressString(True, True),
                byte=byte_str,
                inst=inst
            )

        return instructions

    def disassemble_func(self, func):
        return self.get_function_signature(func) + self.get_instructions(func)

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

    def decompile(self):
        pseudo_c = ''
        for func in self.get_all_functions():
            if not func.isThunk():
                dec_func = self.decompile_func(func)
                if dec_func:
                    pseudo_c += dec_func
        return pseudo_c

    def disassemble(self):
        disasm_result = ''
        for func in self.get_all_functions():
            disasm_result += self.disassemble_func(func)
        return disasm_result

    def list_cross_references(self, dst_func, output_path):
        dst_name = dst_func.getName()
        dst_addr = dst_func.getEntryPoint()
        references = getReferencesTo(dst_addr) # limited to 4096 records
        seen_funcs = set()
        output_lines = []

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
            results = self.decompile_func(src_func)
            for line in results.splitlines():
                if search(dst_name, line):
                    output_lines.append("Call to {} in {} at {} has function signature of: {}".format(
                        dst_name, src_func.getName(), call_addr, line))
                    break

        with open(output_path, 'a') as f:
            f.write('\n'.join(output_lines) + '\n')

    def get_imported_functions(self, output_path):
        import_functions = [

            # Stack overflow roots (unsafe string handling)
            "strcpy",
            "strcat",
            "sprintf",
            "vsprintf",
            "sscanf",
            "snprintf",     
            "strncpy",

            # Heap overflow / heap corruption primitives
            "memcpy",
            "malloc",
            "calloc",
            "realloc",
            "free",

            # Attacker-controlled input sources (network / file)
            "recv",
            "recvfrom",
            "recvmsg",
            "read",
            "readv",
            "fgets",
            "fread",

            # Command execution & RCE pivots
            "system",
            "popen",
            "execl",
            "execlp",
            "execle",
            "execv",
            "execve",
            "execvp",
            "execvpe",

            # Process creation / chaining
            "fork",
            "vfork",
            "posix_spawn",
            "posix_spawnp",

            # Environment-based injection
            "getenv"
        ]


        st = ghidra_app.currentProgram.getSymbolTable()
        si = st.getSymbolIterator()
        symbol_dict = {}
        funcs = []
        while si.hasNext():
            s = si.next()
            if s.getSymbolType() == SymbolType.FUNCTION and not s.isExternal() and s.getName() in import_functions and s.getName() not in symbol_dict:
                symbol_dict[s.getName()] = s.getAddress()
        for address in symbol_dict.values():
            func = ghidra_app.currentProgram.getFunctionManager().getFunctionAt(address)
            funcs.append(func)
        for f in funcs:
            self.list_cross_references(f, output_path)


def run():
    args = ghidra_app.getScriptArgs()
    with open(args[0], 'w') as f:
        f.write('Xref Results \n-----------------------------\n')

    analyzer = Analyzer()
    analyzer.get_imported_functions(args[0])
    decompiled_source_file = args[1]
    disassembly_file = args[3]

    pseudo_c = analyzer.decompile()
    disassembled = analyzer.disassemble()

    with open(decompiled_source_file, 'w') as fw:
        fw.write(pseudo_c)
        print('[*] saving decompilation to -> {}'.format(decompiled_source_file))

    with open(disassembly_file, 'w') as fw:
        fw.write(disassembled)
        print('[*] saving disassembly to -> {}'.format(disassembly_file))

    exporter = CppExporter()
    options = [Option(CppExporter.CREATE_HEADER_FILE, False)]
    exporter.setOptions(options)
    exporter.setExporterServiceProvider(analyzer._tool)
    f = File(args[2])
    exporter.export(f, ghidra_app.currentProgram, None, TaskMonitor.DUMMY)


if __name__ == '__main__':
    run()
