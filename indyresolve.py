import json
from pathlib import Path
from PySide6.QtWidgets import QFileDialog
from binaryninja import (
    PluginCommand,
    BinaryView,
    PossibleValueSet,
    RegisterValueType,
    MediumLevelILOperation,
    log_error,
    log_info
)
import re
import os
from binaryninja.interaction import get_choice_input

from binaryninjaui import UIContext


def pick_file(bv: BinaryView) -> str:
    initial_dir = str(Path(bv.file.filename).parent)
    path, _ = QFileDialog.getOpenFileName(
        None,
        "Select Indirect Call Database",
        initial_dir,
        "JSON Files (*.json);;All Files (*)"
    )
    return path

def indyresolve_import(bv: BinaryView):
    path = pick_file(bv)
    if not path:
        return

    try:

        resolved_map = {}
        with open(path, 'r') as f:
            for line in f:
                if not line.strip(): continue
                source_addr, dest_module, dest_addr = json.loads(line)
                source_addr += bv.start
                if not (source_addr in resolved_map):
                    resolved_map[source_addr] = set()
                
                resolved_map[source_addr].add((dest_module, dest_addr))
                       
    except Exception as e:
        log_error(f"IndyResolve: Error loading JSON: {e}")
        return

    functions_to_process = {
        f for addr in resolved_map 
        for f in bv.get_functions_containing(addr)
    }

    for func in functions_to_process:
        
        for instr in func.mlil.instructions:
            addr = instr.address

            # Process only calls            
            if addr in resolved_map and instr.operation in (
                MediumLevelILOperation.MLIL_CALL,
                MediumLevelILOperation.MLIL_TAILCALL,
                MediumLevelILOperation.MLIL_JUMP,
                MediumLevelILOperation.MLIL_JUMP_TO
            ):
                if instr.operation in (MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_TAILCALL):
                    instr_type = "Call"
                else:
                    instr_type = "Jump"

                targets = resolved_map[addr]
                internal_targets = [t[1] + bv.start for t in targets if t[0] is None]
                external_targets = [t for t in targets if t[0] is not None]

                # Process only unresolved indirect calls
                
                if instr.dest.operation in (MediumLevelILOperation.MLIL_VAR, MediumLevelILOperation.MLIL_LOAD) and instr.dest.possible_values.type in (RegisterValueType.UndeterminedValue, RegisterValueType.NotInSetOfValues):
                    call_var = instr.dest.src
                    
                    # Setting UIDF only make sense if there is only internal targets
                    if len(external_targets) == 0 and instr.dest.operation == MediumLevelILOperation.MLIL_VAR:
                        if len(internal_targets) == 1:
                            # prefer constant if there's a single possible value
                            func.set_user_var_value(call_var, addr, PossibleValueSet.constant(internal_targets[0]), False)
                        else:
                            absval = PossibleValueSet.in_set_of_values(set(internal_targets))
                            func.set_user_var_value(call_var, addr, absval, False)
                    
                    comments = []
                    for t in internal_targets:
                        func.add_user_code_ref(addr, t)
                        sym = bv.get_symbol_at(t)
                        if sym:
                            sym_name = sym.short_name
                        else:
                            sym_name = "sub_" + hex(t)[2:]

                        comments.append(f"Internal {instr_type}: {sym_name} {hex(t)}")

                    for t in external_targets:                        
                        _, _, tab_bv = get_tab_bv_for_file(t[0])
                        sym = None
                        if tab_bv:
                            sym = tab_bv.get_symbol_at(tab_bv.start + t[1])
                        if sym:
                            sym_name = sym.short_name
                        else:
                            if tab_bv:
                                sym_name = "sub_" + hex(tab_bv.start + t[1])[2:]
                            else:
                                sym_name = "UNKNOWN"

                        comments.append(f"External {instr_type}: {sym_name} {hex(t[1])} in {t[0]}")
                    func.set_comment_at(addr, "\n".join(comments))

                    if instr_type == "Jump":                        
                        # Set indirect branch only if intra-function to prevent messing up the analysis
                        branches = [(bv.arch, it) for it in internal_targets if set(bv.get_functions_containing(it)) == set(bv.get_functions_containing(addr))]                        
                        func.set_user_indirect_branches(addr, branches)

            

    bv.update_analysis()
    log_info(f"IndyResolve: Imported resolutions for {len(resolved_map)} addresses.")

def get_tab_bv_for_file(target_lib):
    target_basename = os.path.basename(target_lib)
    for context in UIContext.allContexts():
        for tab in context.getTabs():
            tab_basename = os.path.basename(tab.fileContext().getFilename())
            if tab_basename == target_basename:
                tab_bv = tab.getCurrentBinaryView()
                return context, tab, tab_bv
    return None, None, None

 
def indyresolve_follow(bv: BinaryView, addr: int):
    funcs = bv.get_functions_containing(addr)
    for func in funcs:
        comm = func.get_comment_at(addr)
        if comm != '':
            comms = comm.split('\n')
            external_calls = [line for line in comms if line.startswith("External")]
            idx = get_choice_input("Select external call/jump", "Select external call/jump", external_calls)
            if idx is not None:
                commline = external_calls[idx] 
                match = re.search(r"(0x[0-9a-fA-F]+)\s+in\s+(.+)", commline)
                if match:
                    target_addr = int(match.group(1), 16)
                    target_lib = match.group(2)
                    context, tab, tab_bv = get_tab_bv_for_file(target_lib)
                    if tab_bv:
                        context.activateTab(tab)
                        tab_bv.navigate("Linear:ELF", tab_bv.start + target_addr)

                    



PluginCommand.register(
    "Import indirect call database",
    "Import resolved indirect calls and apply them to MLIL.",
    indyresolve_import
)

PluginCommand.register_for_address(
    "Follow indirect external call/jump",
    "Follow indirect calls/jumps to external libraries",
    indyresolve_follow,
)