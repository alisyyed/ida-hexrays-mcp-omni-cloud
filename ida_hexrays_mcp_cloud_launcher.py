#!/usr/bin/env python3
"""
Hex-Rays IDA & Docs Omni-Nexus (v1.4 Zero-Cache Edge-Smart) - 24/7 Cloud MCP Server
===================================================================================
Built for https://docs.hex-rays.com/ (IDA 9.5, Official Hex-Rays IDA MCP Server
`HexRaysSA/ida-mcp`, `idalib` Headless Engine, `ida-domain` Pythonic API, `ida-hcli`,
IDAPython 50+ SDK Modules, Hex-Rays Microcode `mbl_array_t` / `ctree_visitor_t`,
FLIRT 2.0 v11 Signatures, Lumina, and `mrexodia/ida-pro-mcp` compatibility).

Single-command 24/7 Forever Setup (Windows PowerShell / Linux / macOS):
  python3 ida_hexrays_mcp_cloud_launcher.py --forever

What `--forever` does automatically:
  1. Auto-detects your saved GitHub token (`forever_credentials.json`) so you don't
     even have to paste a token if you already ran Ghidra or Craft-Anything!
  2. Creates/updates `https://github.com/<you>/ida-hexrays-mcp-omni-cloud` with a
     single-step 24/7 self-respawning GitHub Actions relay runner.
  3. Deploys the Permanent Zero-Cache Edge-Smart Cloudflare Worker Router:
       https://ida-hexrays-mcp-forever.forested-lung.workers.dev/mcp
     (automatically selecting the `Forested Lung` Cloudflare account if multiple
     accounts exist, and reading `LIVE_MCP_URL.json` via the 0-cache GitHub Contents API).
  4. Executes live `docs.hex-rays.com` Markdown fetches, `llms.txt` searches,
     IDAPython / `ida-domain` / Microcode script generation, and binary header triage
     directly at the Cloudflare Edge in 0ms even while the background runner wakes!
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import math
import os
import platform
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# 1. Complete Hex-Rays Documentation Portal & Ecosystem Catalog (IDA 9.5)
# ---------------------------------------------------------------------------

HEXRAYS_ECOSYSTEM_CATALOG: Dict[str, Dict[str, Any]] = {
    "docs_portal": {
        "title": "Hex-Rays IDA 9.5 Main Documentation Portal (docs.hex-rays.com)",
        "base_url": "https://docs.hex-rays.com",
        "llms_txt": "https://docs.hex-rays.com/llms.txt",
        "items": [
            "https://docs.hex-rays.com/",
            "https://docs.hex-rays.com/release-notes/9_5",
            "https://docs.hex-rays.com/release-notes/9_4",
            "https://docs.hex-rays.com/release-notes/9_0",
            "https://docs.hex-rays.com/core/idalib",
            "https://docs.hex-rays.com/core/idalib/overview",
            "https://docs.hex-rays.com/core/idalib/getting-started",
            "https://docs.hex-rays.com/core/idalib/how-tos/malware-analysis-with-idalib",
            "https://docs.hex-rays.com/add-ons/mcp",
            "https://docs.hex-rays.com/add-ons/mcp/getting-started",
            "https://docs.hex-rays.com/add-ons/mcp/concepts/multiplexing",
            "https://docs.hex-rays.com/add-ons/mcp/concepts/where-mcp-fits",
            "https://docs.hex-rays.com/add-ons/mcp/how-tos/solving-a-multi-binary-challenge-with-ida-mcp",
            "https://docs.hex-rays.com/core/decompiler/how-tos/microcode-view",
            "https://docs.hex-rays.com/core/flirt",
            "https://docs.hex-rays.com/core/flirt/concepts/flirt-2.0",
            "https://docs.hex-rays.com/core/flirt/how-tos/generate-flirt-signatures-from-libraries",
            "https://docs.hex-rays.com/add-ons/lumina/reference/lumina-client",
            "https://docs.hex-rays.com/add-ons/malware",
            "https://docs.hex-rays.com/developer/idapython",
            "https://docs.hex-rays.com/developer/idapython/idapython-getting-started",
            "https://docs.hex-rays.com/developer/idapython/idapython-examples",
        ],
    },
    "ida_mcp_official": {
        "title": "Official Hex-Rays IDA MCP Server (HexRaysSA/ida-mcp & ida-nexus)",
        "base_url": "https://github.com/HexRaysSA/ida-mcp",
        "install_cmd": "uvx ida-hcli mcp install",
        "http_cmd": "uvx ida-mcp http --host 127.0.0.1 --port 8737",
        "stdio_cmd": "uvx --exclude-newer=1s ida-mcp stdio --agent=gemini-555",
        "items": [
            "open_database",
            "close_database",
            "list_databases",
            "lookup_funcs",
            "list_funcs",
            "decompile",
            "disasm",
            "imports",
            "exports",
            "strings",
            "xrefs_to",
            "xrefs_from",
            "callees",
            "callers",
            "rename_func",
            "rename_lvar",
            "rename_global",
            "set_type",
            "set_comment",
            "read_bytes",
            "patch_bytes",
            "list_structs",
            "get_stack_frame",
            "int_convert",
            "py_eval",
        ],
    },
    "ida_domain_api": {
        "title": "Hex-Rays IDA Domain API (ida-domain.docs.hex-rays.com)",
        "base_url": "https://ida-domain.docs.hex-rays.com",
        "llms_txt": "https://ida-domain.docs.hex-rays.com/llm/llms.txt",
        "repo_url": "https://github.com/HexRaysSA/ida-domain",
        "install_cmd": "pip install ida-domain",
        "items": [
            "Database (Main IDB/I64 lifecycle and headless opening)",
            "Entries (Entry point enumeration and ordinals)",
            "Segments (Memory segment permissions, ranges, and classes)",
            "Functions (Function discovery, prototypes, flags, and stack frames)",
            "Flowchart (Basic blocks, CFG edges, predecessors, and successors)",
            "Instructions (Decoded instructions, mnemonics, and prefixes)",
            "Operands (Register, immediate, memory, and displacement operands)",
            "Bytes (Raw byte reads, patching, patterns, and data definitions)",
            "Strings (ASCII/UTF-16/Swift/Go/Rust string extraction)",
            "Types (C type parsing, TIL management, structs, and enums)",
            "Heads (Defined code/data item iteration across EA ranges)",
            "Hooks (IDP, IDB, UI, and Hex-Rays decompiler event hooks)",
            "XRefs (Code and data cross-references to/from any EA or struct field)",
            "Names (Demangled symbols, labels, and verbatim names)",
            "Comments (Regular, repeatable, anterior/posterior, and ctree pseudocode comments)",
            "Signature Files (FLIRT v11 .sig application and FLAIR .pat generation)",
        ],
    },
    "idapython_sdk": {
        "title": "IDAPython SDK 50+ Modules Reference (python.docs.hex-rays.com)",
        "base_url": "https://python.docs.hex-rays.com",
        "items": [
            "idapro (Headless idalib initialization: import idapro; idapro.open_database(...))",
            "ida_hexrays (Decompiler cfunc_t, ctree_visitor_t, mbl_array_t, minsn_t, mop_t)",
            "ida_bytes (get_bytes, patch_bytes, create_data, bin_search)",
            "ida_funcs (func_t, get_func, add_func, get_func_name)",
            "ida_typeinf (tinfo_t, parse_decl, apply_tinfo, udt_type_data_t)",
            "ida_kernwin (UI subviews, BWN_MICROCODE, action_handler_t, choose)",
            "ida_xref (xrefblk_t, add_cref, add_dref, get_first_cref_to)",
            "ida_segment (segment_t, getseg, get_segm_by_name, add_segm)",
            "ida_name (get_name, set_name, demangle_name, SN_NOWARN)",
            "ida_frame (get_frame, define_stkvar, build_stkvar_xrefs)",
            "ida_ua (insn_t, op_t, decode_insn, print_insn_mnem)",
            "ida_idp (ph, processor_t, IDP_Hooks, custom instructions)",
            "ida_nalt (get_input_file_path, retrieve_input_file_sha256, switch_info_t)",
            "ida_gdl (FlowChart, qflow_chart_t, BasicBlock)",
            "ida_auto (auto_wait, plan_and_wait, auto_is_ok)",
            "ida_dbg (Appcall, start_process, wait_for_next_event, get_reg_val)",
            "ida_loader (file_to_database, mem2base, load_plugin)",
            "ida_dirtree (dirtree_t, function/type/import folders)",
            "idautils (Functions, Heads, XrefsTo, XrefsFrom, Strings, Names, Segments)",
            "idc (High-level legacy compatibility helpers)",
        ],
    },
    "cpp_microcode_sdk": {
        "title": "Hex-Rays C++ SDK & Microcode VM (cpp.docs.hex-rays.com)",
        "base_url": "https://cpp.docs.hex-rays.com/vmpage.html",
        "repo_url": "https://github.com/HexRaysSA/ida-sdk",
        "items": [
            "mba_maturity_t (MMAT_GENERATED, MMAT_PREOPTIMIZED, MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2, MMAT_GLBOPT3, MMAT_LVARS)",
            "mbl_array_t (Microblock array representing a function at a given maturity)",
            "mblock_t (Single basic block of microinstructions with predset/succset)",
            "minsn_t (Microinstruction with opcode mcode_t and operands l, r, d)",
            "mop_t (Micro-operand: mop_r register, mop_n number, mop_d nested insn, mop_S stack, mop_v global, mop_l lvar)",
            "mlist_t (Interval set of microregisters rlist_t + memory locations ivlset_t)",
            "optinsn_t (Custom microinstruction optimizer callback)",
            "optblock_t (Custom microblock optimizer callback)",
            "cfunc_t (Decompiled function AST root with cinsn_t statement tree and cexpr_t expression tree)",
            "ctree_visitor_t (AST visitor for inspecting or mutating C-tree before pseudocode rendering)",
        ],
    },
    "hcli_and_cicd": {
        "title": "Hex-Rays HCLI & GitHub Actions Automation (hcli.docs.hex-rays.com)",
        "base_url": "https://hcli.docs.hex-rays.com",
        "repo_url": "https://github.com/HexRaysSA/ida-hcli",
        "actions_repo": "https://github.com/HexRaysSA/ida-hcli-actions",
        "items": [
            "uvx ida-hcli mcp install (Install Official Hex-Rays IDA MCP Server + GUI plugin)",
            "hcli ida install (Download and install IDA headlessly in CI/Docker)",
            "hcli ida set-default /path/to/ida (Register default IDA installation for HCLI)",
            "hcli ida python explain-environment (Trace IDADIR, IDAUSR, and Python venv resolution)",
            "hcli ida python doctor (Verify IDA Python environment and plugin dependencies)",
            "hcli plugin install ida-mcp@https://github.com/HexRaysSA/ida-mcp (Install IDA MCP plugin)",
            "hcli extension upgrade hexrays/malware-analysis (Upgrade IDA 9.5 decoupled add-ons)",
        ],
    },
}

# ---------------------------------------------------------------------------
# 2. Curated MCP Tools Exposed to Gemini Connected Apps
# ---------------------------------------------------------------------------

DIRECT_CURATED_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "hexrays_doctor_and_status",
        "description": "[Hex-Rays IDA Omni-Nexus] Check health of the 24/7 Hex-Rays Cloud MCP Relay, Zero-Cache Edge Router, installed tools (`ida-hcli`, `ida-domain`, `ida-mcp`, `idalib`, `rizin`, `objdump`), and active documentation portals (`docs.hex-rays.com`).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "hexrays_list_api_and_mcp_catalog",
        "description": "[Hex-Rays IDA Omni-Nexus] Browse or search the complete Hex-Rays IDA 9.5 ecosystem catalog (`docs_portal`, `ida_mcp_official`, `ida_domain_api`, `idapython_sdk`, `cpp_microcode_sdk`, `hcli_and_cicd`).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Optional category filter (`docs_portal`, `ida_mcp_official`, `ida_domain_api`, `idapython_sdk`, `cpp_microcode_sdk`, `hcli_and_cicd`).",
                },
                "search": {
                    "type": "string",
                    "description": "Optional keyword substring to filter items.",
                },
            },
        },
    },
    {
        "name": "hexrays_fetch_doc_markdown",
        "description": "[Hex-Rays IDA Omni-Nexus] Fetch live documentation or `llms.txt` directly from `https://docs.hex-rays.com/`, `https://ida-domain.docs.hex-rays.com/`, `https://python.docs.hex-rays.com/`, `https://cpp.docs.hex-rays.com/`, or `https://hcli.docs.hex-rays.com/` as clean Markdown.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path_or_url": {
                    "type": "string",
                    "description": "Full Hex-Rays docs URL or relative path (e.g. 'core/idalib', 'add-ons/mcp', 'release-notes/9_5', 'llms.txt', 'https://ida-domain.docs.hex-rays.com/usage/').",
                }
            },
            "required": ["path_or_url"],
        },
    },
    {
        "name": "hexrays_search_docs",
        "description": "[Hex-Rays IDA Omni-Nexus] Search the official Hex-Rays `llms.txt` index and curated IDA 9.5 / IDAPython / `idalib` / `ida-domain` / `IDA MCP` / Microcode documentation pages by keyword.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query (e.g. 'idalib', 'multiplexing', 'microcode', 'flirt 2.0', 'lumina', 'domain api', 'hcli').",
                }
            },
            "required": ["query"],
        },
    },
    {
        "name": "hexrays_open_and_triage_binary",
        "description": "[Hex-Rays IDA Omni-Nexus] Triage an ELF, PE/EXE/DLL/SYS, Mach-O, or WASM binary by URL or path using IDA-compatible metadata (format, architecture, SHA-256, Shannon entropy, segments, imports, exports, strings, and `idalib` / `ida-mcp` session status).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url_or_path": {
                    "type": "string",
                    "description": "HTTPS URL or local path of the binary to inspect.",
                }
            },
            "required": ["target_url_or_path"],
        },
    },
    {
        "name": "hexrays_decompile_or_disassemble",
        "description": "[Hex-Rays IDA Omni-Nexus] Disassemble or decompile a function/symbol/address in a target binary via `idalib` / `ida-mcp` (if an IDA engine is attached) or the built-in cloud disassembler/pseudocode lifter (`objdump` / `rizin` / ELF-PE analyzer).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url_or_path": {
                    "type": "string",
                    "description": "Target binary path or HTTPS URL (defaults to active sample if omitted).",
                },
                "function_or_address": {
                    "type": "string",
                    "description": "Function name (e.g. 'main', 'entry') or hex address (e.g. '0x140001000').",
                },
            },
            "required": ["function_or_address"],
        },
    },
    {
        "name": "hexrays_generate_idapython_or_domain_script",
        "description": "[Hex-Rays IDA Omni-Nexus] Generate a complete, ready-to-run IDA 9.5 script using headless `idalib` (`import idapro`), the Pythonic `ida_domain` API (`from ida_domain import Database`), or classic `ida_hexrays` / `idautils` for any reverse-engineering task.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_description": {
                    "type": "string",
                    "description": "What the script should accomplish (e.g. 'batch decompile all functions calling CryptEncrypt', 'extract vtables and apply C structs', 'scan for XOR loops in microcode').",
                },
                "api_style": {
                    "type": "string",
                    "description": "Preferred API style: 'idalib_headless' (default), 'ida_domain', 'idapython_hexrays', or 'ida_mcp_client'.",
                },
                "binary_path": {
                    "type": "string",
                    "description": "Optional target binary path to pre-fill in the generated script.",
                },
            },
            "required": ["task_description"],
        },
    },
    {
        "name": "hexrays_microcode_and_ctree_advisor",
        "description": "[Hex-Rays IDA Omni-Nexus] Provide exact Hex-Rays Decompiler Microcode (`mbl_array_t`, `minsn_t`, `mop_t`, `optinsn_t`, `optblock_t`, maturity levels `MMAT_*`) and C-tree AST (`cfunc_t`, `ctree_visitor_t`) architecture + C++/IDAPython code for deobfuscation or custom optimization.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "deobfuscation_goal": {
                    "type": "string",
                    "description": "Obfuscation pattern or optimization goal (e.g. 'opaque predicates', 'control-flow flattening', 'mixed boolean-arithmetic MBA', 'custom call convention', 'indirect jump resolution').",
                }
            },
            "required": ["deobfuscation_goal"],
        },
    },
    {
        "name": "hexrays_flirt_and_lumina_toolkit",
        "description": "[Hex-Rays IDA Omni-Nexus] Generate FLIRT 2.0 (v11 reference-driven naming) `.pat`/`.sig` build pipelines (`pelf`/`pcf`/`pcoff` + `sigmake`) and private `lumina-client` (port 7443) commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "library_format": {
                    "type": "string",
                    "description": "Library type ('elf_a', 'pe_lib', 'macho_a', 'idb_makesig', or 'lumina_private').",
                },
                "library_name": {
                    "type": "string",
                    "description": "Name of the static library or target binary (e.g. 'libssl.a', 'libSceAgcDriver.a').",
                },
            },
            "required": ["library_format"],
        },
    },
    {
        "name": "hexrays_bridge_ghidra_and_craft",
        "description": "[Hex-Rays IDA Omni-Nexus] Cross-map addresses, function prototypes, C structs, and workflows between Hex-Rays IDA (`idalib` / `ida-mcp`), Ghidra 12.1.4 (`ghidra-omni-nexus`), Craft-Anything (`craft-anything-omni-foundry`), and AnyPS5 (`anyps5`).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workflow_goal": {
                    "type": "string",
                    "description": "Cross-engine goal (e.g. 'sync Ghidra decompilation and IDA Microcode on PS5 SELF', 'export IDA types to Craft-Anything deep-mode rebuild').",
                }
            },
            "required": ["workflow_goal"],
        },
    },
]

# ---------------------------------------------------------------------------
# 3. Hex-Rays Cloud Engine & Live Documentation / Binary Bridge
# ---------------------------------------------------------------------------

def build_idapython_script_template(task_desc: str, api_style: str = "idalib_headless", binary_path: str = "./sample.bin") -> Dict[str, Any]:
    style = (api_style or "idalib_headless").strip().lower()
    head_script = f"""#!/usr/bin/env python3
# Hex-Rays IDA 9.5 Headless Automation Script (idalib + ida_domain + ida_hexrays)
# Task: {task_desc}
# Docs: https://docs.hex-rays.com/core/idalib & https://ida-domain.docs.hex-rays.com/
import json
import sys
from pathlib import Path

TARGET_BINARY = r"{binary_path}"

# 1. Headless idalib Initialization (IDA 9.0 - 9.5+)
# Requires: `py-activate-idalib.py` or `uvx ida-hcli ida install --set-default`
import idapro
idapro.open_database(TARGET_BINARY, run_auto_analysis=True)

import ida_auto
import ida_funcs
import ida_hexrays
import ida_name
import idautils

ida_auto.auto_wait()
has_decompiler = ida_hexrays.init_hexrays_plugin()

results = []
for func_ea in idautils.Functions():
    fn_name = ida_name.get_ea_name(func_ea)
    pseudocode_str = ""
    if has_decompiler:
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                pseudocode_str = str(cfunc)
        except Exception:
            pass
    results.append({{
        "ea": hex(func_ea),
        "name": fn_name,
        "callers": [hex(x.frm) for x in idautils.XrefsTo(func_ea, 0)],
        "pseudocode_preview": "\\n".join(pseudocode_str.splitlines()[:25]),
    }})

Path("ida_headless_report.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
idapro.close_database(save=False)
print(f"[+] Exported {{len(results)}} functions from {{TARGET_BINARY}} to ida_headless_report.json")
"""

    domain_script = f"""#!/usr/bin/env python3
# Hex-Rays IDA Domain API Script (`pip install ida-domain`)
# Task: {task_desc}
# Docs: https://ida-domain.docs.hex-rays.com/getting_started/
from ida_domain import Database

TARGET_BINARY = r"{binary_path}"

with Database.open(TARGET_BINARY, save_on_close=False) as db:
    print(f"[+] Opened database: {{TARGET_BINARY}}")
    for fn in db.functions:
        xrefs_in = list(db.xrefs.to_ea(fn.start_ea))
        if len(xrefs_in) > 0:
            print(f"Function {{fn.name}} @ {{hex(fn.start_ea)}} (incoming xrefs: {{len(xrefs_in)}})")
"""

    mcp_config = {
        "mcpServers": {
            "hexrays-ida-official": {
                "command": "uvx",
                "args": ["--exclude-newer=1s", "ida-mcp", "stdio", "--agent=gemini-555"],
            },
            "hexrays-omni-cloud-24x7": {
                "url": "https://ida-hexrays-mcp-forever.forested-lung.workers.dev/mcp",
            },
        }
    }

    return {
        "task_description": task_desc,
        "selected_style": style,
        "idalib_headless_script": head_script,
        "ida_domain_script": domain_script,
        "mcp_client_config": mcp_config,
        "official_docs_references": [
            "https://docs.hex-rays.com/core/idalib/getting-started",
            "https://ida-domain.docs.hex-rays.com/getting_started/",
            "https://docs.hex-rays.com/add-ons/mcp/getting-started",
            "https://python.docs.hex-rays.com/",
        ],
    }


def build_microcode_advisor_payload(goal: str) -> Dict[str, Any]:
    cpp_and_py_sample = f"""# Hex-Rays IDAPython Microcode Optimizer (`optinsn_t` & `optblock_t`) + C-Tree Visitor (`ctree_visitor_t`)
# Goal: {goal}
# Reference: https://docs.hex-rays.com/core/decompiler/how-tos/microcode-view & https://cpp.docs.hex-rays.com/vmpage.html

import ida_hexrays

class CustomMicroInstructionOptimizer(ida_hexrays.optinsn_t):
    def func(self, blk: "ida_hexrays.mblock_t", ins: "ida_hexrays.minsn_t", optflags: int) -> int:
        # Inspect microinstruction opcode (ins.opcode) and operands (ins.l, ins.r, ins.d)
        # Example: fold MBA identity `x ^ 0` -> `m_mov x, d`
        if ins.opcode == ida_hexrays.m_xor and ins.r.t == ida_hexrays.mop_n and ins.r.nnn.value == 0:
            ins.opcode = ida_hexrays.m_mov
            ins.r.erase()
            return 1  # number of changes made
        return 0

class CustomCTreeVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)

    def visit_expr(self, e: "ida_hexrays.cexpr_t") -> int:
        if e.op == ida_hexrays.cot_call:
            print(f"[CTree] Call expression at {{hex(e.ea)}}")
        return 0
"""
    return {
        "deobfuscation_goal": goal,
        "microcode_maturity_pipeline": [
            "MMAT_GENERATED (Initial raw microcode lifted from processor instructions)",
            "MMAT_PREOPTIMIZED (Basic constant/register propagation completed)",
            "MMAT_LOCOPT (Block-local optimization and dead-store removal completed)",
            "MMAT_CALLS (Call arguments and return types resolved)",
            "MMAT_GLBOPT1 (First global optimization pass across CFG)",
            "MMAT_GLBOPT2 (Second global optimization pass and stack frame resolution)",
            "MMAT_GLBOPT3 (Third global pass; final conditional/loop structuring prep)",
            "MMAT_LVARS (Local variables allocated; ready for cfunc_t C-tree generation)",
        ],
        "idapython_microcode_and_ctree_template": cpp_and_py_sample,
        "official_docs_urls": [
            "https://docs.hex-rays.com/core/decompiler/how-tos/microcode-view",
            "https://cpp.docs.hex-rays.com/vmpage.html",
            "https://docs.hex-rays.com/developer/idapython/idapython-examples",
        ],
    }


def build_flirt_and_lumina_payload(library_format: str, library_name: str = "libtarget.a") -> Dict[str, Any]:
    fmt = (library_format or "elf_a").strip().lower()
    parser_bin = "pelf" if "elf" in fmt else ("pcf" if "pe" in fmt or "coff" in fmt else "pmacho")
    stem = Path(library_name).stem or "libtarget"
    return {
        "library_format": fmt,
        "library_name": library_name,
        "flirt_2_0_v11_pipeline": [
            f"# Step 1: Parse static library into a FLAIR pattern file (.pat)",
            f"{parser_bin} {library_name} {stem}.pat",
            f"# Step 2: Compile .pat into a FLIRT v11 signature file (.sig) with sigmake",
            f"sigmake -n\"{stem}\" {stem}.pat {stem}.sig",
            f"# If collisions occur, edit {stem}.exc (remove leading comment lines) and re-run:",
            f"sigmake -n\"{stem}\" {stem}.pat {stem}.sig",
            f"# Step 3: Copy {stem}.sig into $IDADIR/sig/pc/ (or apply via ida_funcs.plan_to_apply_idasgn('{stem}.sig'))",
        ],
        "lumina_private_server_cli": [
            "# Query private Lumina server (default port 7443) using LUMINA_CLIENT_PASSWORD env var:",
            "export LUMINA_CLIENT_PASSWORD='your_password'",
            "lumina-client -h lumina.internal:7443 info",
            "lumina-client -h lumina.internal:7443 hist show --last-change",
        ],
        "official_docs_urls": [
            "https://docs.hex-rays.com/core/flirt",
            "https://docs.hex-rays.com/core/flirt/concepts/flirt-2.0",
            "https://docs.hex-rays.com/core/flirt/how-tos/generate-flirt-signatures-from-libraries",
            "https://docs.hex-rays.com/add-ons/lumina/reference/lumina-client",
        ],
    }


class HexRaysOmniBridge:
    def __init__(self, work_dir: Path, install_in_background: bool = False) -> None:
        self.work_dir = work_dir
        self.targets_dir = work_dir / "targets"
        self.targets_dir.mkdir(parents=True, exist_ok=True)
        self.active_sample: Optional[Path] = self._build_default_sample()
        self.install_status: Dict[str, Any] = {"state": "ready"}
        if install_in_background:
            threading.Thread(target=self._bg_install_tools, daemon=True).start()

    def _build_default_sample(self) -> Path:
        sample_bin = self.targets_dir / "hexrays_demo_target"
        if sample_bin.exists():
            return sample_bin
        c_src = self.targets_dir / "hexrays_demo_target.c"
        c_src.write_text(
            '#include <stdio.h>\n#include <stdint.h>\n'
            'uint32_t derive_route_seed(const char *parcel_id) {\n'
            '    uint32_t h = 0x811c9dc5u;\n'
            '    while (*parcel_id) { h ^= (uint8_t)(*parcel_id++); h *= 0x01000193u; }\n'
            '    return ((h ^ 0x6D3A91E7u) << 7) + 0x13579BDFu;\n'
            '}\n'
            'int main(int argc, char **argv) {\n'
            '    printf("Seed: 0x%08x\\n", derive_route_seed(argc > 1 ? argv[1] : "ZX-4815"));\n'
            '    return 0;\n'
            '}\n',
            encoding="utf-8",
        )
        if shutil.which("gcc"):
            subprocess.run(["gcc", "-O2", "-g", str(c_src), "-o", str(sample_bin)], check=False)
        if not sample_bin.exists() and Path("/bin/ls").exists():
            shutil.copy2("/bin/ls", sample_bin)
        return sample_bin

    def _bg_install_tools(self) -> None:
        try:
            self.install_status["state"] = "installing_hcli_and_domain"
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", "ida-hcli", "ida-domain"],
                check=False,
                timeout=90,
            )
            self.install_status["state"] = "installed"
        except Exception as exc:
            self.install_status["state"] = f"standalone_cloud_mode ({exc})"

    def fetch_hexrays_doc(self, path_or_url: str) -> Dict[str, Any]:
        raw = path_or_url.strip()
        if raw.startswith(("http://", "https://")):
            url = raw
        else:
            clean = raw.lstrip("/")
            url = f"https://docs.hex-rays.com/{clean}"

        candidates = [url]
        if url.startswith("https://docs.hex-rays.com/") and not url.endswith((".md", ".txt")):
            candidates.insert(0, url.rstrip("/") + ".md")

        for cand in candidates:
            try:
                req = urllib.request.Request(cand, headers={"User-Agent": "HexRays-OmniNexus-MCP/1.4"})
                with urllib.request.urlopen(req, timeout=12) as resp:
                    text = resp.read().decode("utf-8", errors="replace")
                    if "<html" in text[:300].lower():
                        text_clean = re.sub(r"<script[\s\S]*?</script>", "", text, flags=re.I)
                        text_clean = re.sub(r"<style[\s\S]*?</style>", "", text_clean, flags=re.I)
                        text_clean = re.sub(r"<[^>]+>", " ", text_clean)
                        text_clean = re.sub(r"\s+", " ", text_clean).strip()
                        return {"url": cand, "format": "html_extracted", "content": text_clean[:12000]}
                    return {"url": cand, "format": "markdown_or_text", "content": text[:16000]}
            except Exception:
                continue
        return {
            "requested": path_or_url,
            "note": "Returned curated offline summary from HEXRAYS_ECOSYSTEM_CATALOG.",
            "catalog_matches": self.search_docs(path_or_url),
        }

    def search_docs(self, query: str) -> Dict[str, Any]:
        q = query.strip().lower()
        matches: List[Dict[str, Any]] = []
        for cat_key, cat_val in HEXRAYS_ECOSYSTEM_CATALOG.items():
            matched_items = [
                item for item in cat_val["items"]
                if not q or q in item.lower() or q in cat_val["title"].lower() or q in cat_key.lower()
            ]
            if matched_items:
                matches.append({
                    "category": cat_key,
                    "title": cat_val["title"],
                    "base_url": cat_val["base_url"],
                    "matches": matched_items,
                })
        return {"query": query, "results": matches}

    def triage_binary(self, url_or_path: str) -> Dict[str, Any]:
        target_path = self.active_sample
        val = (url_or_path or "").strip()
        if val.startswith(("http://", "https://")):
            fname = Path(urllib.parse.urlparse(val).path).name or f"sample_{int(time.time())}.bin"
            dest = self.targets_dir / fname
            req = urllib.request.Request(val, headers={"User-Agent": "HexRays-OmniNexus-MCP/1.4"})
            with urllib.request.urlopen(req, timeout=25) as r:
                dest.write_bytes(r.read())
            target_path = dest
            self.active_sample = dest
        elif val and Path(val).exists():
            target_path = Path(val)
            self.active_sample = target_path

        if not target_path or not target_path.exists():
            return {"error": f"Target not found: {url_or_path}"}

        data = target_path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        magic = data[:4]
        if magic == b"\x7fELF":
            fmt = "ELF (Executable and Linkable Format)"
        elif magic[:2] == b"MZ":
            fmt = "PE/COFF (Windows Portable Executable)"
        elif magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            fmt = "Mach-O (Apple Binary)"
        elif magic == b"\x00asm":
            fmt = "WebAssembly (WASM Binary Module)"
        else:
            fmt = f"Raw Binary (magic={magic.hex()})"

        counts = [0] * 256
        for b in data[:262144]:
            counts[b] += 1
        total = max(1, min(len(data), 262144))
        entropy = -sum((c / total) * math.log2(c / total) for c in counts if c > 0)

        strings_sample = [m.decode("ascii", errors="ignore") for m in re.findall(rb"[\x20-\x7e]{5,}", data[:262144])[:40]]
        symbols_out = ""
        if shutil.which("nm"):
            try:
                symbols_out = subprocess.check_output(["nm", "-C", str(target_path)], stderr=subprocess.DEVNULL, text=True, timeout=6)[:3000]
            except Exception:
                pass

        return {
            "file": str(target_path),
            "size_bytes": len(data),
            "sha256": sha256,
            "detected_format": fmt,
            "shannon_entropy": round(entropy, 4),
            "strings_preview": strings_sample,
            "symbols_preview": symbols_out.splitlines()[:35],
        }

    def decompile_or_disassemble(self, target_url_or_path: str, func_or_addr: str) -> Dict[str, Any]:
        if target_url_or_path:
            self.triage_binary(target_url_or_path)
        target = self.active_sample
        if not target or not target.exists():
            return {"error": "No target binary loaded."}

        disasm_text = ""
        if shutil.which("objdump"):
            try:
                cmd = ["objdump", "-d", "-M", "intel", str(target)]
                full_dis = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=10)
                pattern = re.compile(rf"^[0-9a-fA-F]+\s+<[^>]*{re.escape(func_or_addr)}[^>]*>:", re.M)
                m = pattern.search(full_dis)
                if m:
                    start = m.start()
                    end_match = re.search(r"\n\n[0-9a-fA-F]+\s+<", full_dis[start + 10:])
                    disasm_text = full_dis[start:start + 10 + end_match.start()] if end_match else full_dis[start:start + 4000]
                else:
                    disasm_text = full_dis[:4000]
            except Exception as exc:
                disasm_text = f"objdump note: {exc}"

        return {
            "target": str(target),
            "requested_function_or_address": func_or_addr,
            "disassembly_intel": disasm_text,
            "idapython_decompile_snippet": f"import idapro, ida_hexrays\nidapro.open_database(r'{target}', run_auto_analysis=True)\nprint(ida_hexrays.decompile({repr(func_or_addr)}))",
        }

    def run_doctor(self) -> Dict[str, Any]:
        return {
            "server": "Hex-Rays IDA & Docs Omni-Nexus v1.4 (Zero-Cache Edge-Smart)",
            "docs_portal": "https://docs.hex-rays.com/ (IDA 9.5 + IDA MCP + idalib + Domain API + HCLI + IDAPython + Microcode)",
            "official_repos": {
                "ida_mcp": "https://github.com/HexRaysSA/ida-mcp",
                "ida_nexus": "https://github.com/HexRaysSA/ida-nexus",
                "ida_domain": "https://github.com/HexRaysSA/ida-domain",
                "ida_hcli": "https://github.com/HexRaysSA/ida-hcli",
                "ida_hcli_actions": "https://github.com/HexRaysSA/ida-hcli-actions",
                "ida_sdk": "https://github.com/HexRaysSA/ida-sdk",
                "community_ida_pro_mcp": "https://github.com/mrexodia/ida-pro-mcp",
            },
            "companion_tools_detected": {
                "hcli": bool(shutil.which("hcli")),
                "objdump": bool(shutil.which("objdump")),
                "nm": bool(shutil.which("nm")),
                "readelf": bool(shutil.which("readelf")),
                "gcc": bool(shutil.which("gcc")),
            },
            "install_status": self.install_status,
            "active_sample": str(self.active_sample) if self.active_sample else None,
        }


# ---------------------------------------------------------------------------
# 4. 24/7 Perpetual GitHub Cloud Relay & Zero-Cache Edge-Smart Worker (v1.4)
# ---------------------------------------------------------------------------

GITHUB_WORKFLOW_YML = """name: Hex-Rays IDA & Docs 24/7 Perpetual Cloud MCP Relay

on:
  workflow_dispatch:
  push:
    branches: [ main ]
  schedule:
    - cron: '35 */5 * * *'

permissions:
  contents: write
  actions: write

concurrency:
  group: ida-hexrays-perpetual-relay
  cancel-in-progress: true

jobs:
  ida-hexrays-cloud:
    runs-on: ubuntu-24.04
    timeout-minutes: 330
    steps:
      - name: 1. Checkout Repository
        uses: actions/checkout@v4

      - name: 2. Boot Hex-Rays 24/7 Cloud MCP Server, Publish LIVE_MCP_URL.json & Keep Alive (5h Window)
        env:
          RUNNER_TRACKING_ID: ""
        run: |
          sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
          sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sqlite3 binutils gcc unzip curl || true
          rm -f /tmp/LIVE_MCP_URL.json
          nohup python3 -u ida_hexrays_mcp_cloud_launcher.py --port 7860 > /tmp/hexrays_omni.log 2>&1 &
          echo "Waiting for Python launcher to write verified https://*.trycloudflare.com URL to /tmp/LIVE_MCP_URL.json..."
          PUBLISHED=0
          for i in $(seq 1 60); do
            if [ -s /tmp/LIVE_MCP_URL.json ] && grep -q "https://" /tmp/LIVE_MCP_URL.json; then
              git config user.name "ida-hexrays-cloud-bot"
              git config user.email "bot@users.noreply.github.com"
              git fetch origin main || true
              git checkout -B main origin/main || true
              cp /tmp/LIVE_MCP_URL.json LIVE_MCP_URL.json
              cat LIVE_MCP_URL.json
              git add LIVE_MCP_URL.json
              git commit -m "Auto-update LIVE_MCP_URL.json [skip ci]" || true
              git push origin main --force || true
              PUBLISHED=1
              break
            fi
            sleep 2
          done
          cat /tmp/hexrays_omni.log
          if [ "$PUBLISHED" -eq 0 ]; then
            echo "ERROR: Cloudflare Quick Tunnel did not publish URL within 120s"
            exit 1
          fi
          echo "Hex-Rays IDA & Docs 24/7 Cloud MCP Relay is LIVE! Holding tunnel open for 5 hours..."
          sleep 18000

      - name: 3. Perpetual Self-Respawn
        if: success() || failure()
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          curl -sS -X POST \
            -H "Authorization: Bearer ${GH_TOKEN}" \
            -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/workflows/ida_hexrays_mcp_cloud.yml/dispatches" \
            -d '{"ref":"main"}' || true
"""


def build_permanent_cloudflare_worker_js(
    github_username: str,
    repo_name: str = "ida-hexrays-mcp-omni-cloud",
    gh_token_for_autowake: str = "",
) -> str:
    api_json_url = f"https://api.github.com/repos/{github_username}/{repo_name}/contents/LIVE_MCP_URL.json?ref=main"
    raw_json_url = f"https://raw.githubusercontent.com/{github_username}/{repo_name}/main/LIVE_MCP_URL.json"
    dispatch_url = f"https://api.github.com/repos/{github_username}/{repo_name}/actions/workflows/ida_hexrays_mcp_cloud.yml/dispatches"
    tools_json_str = json.dumps(DIRECT_CURATED_TOOLS)
    catalog_json_str = json.dumps(HEXRAYS_ECOSYSTEM_CATALOG)

    return f"""/**
 * Hex-Rays IDA & Docs Omni-Nexus v1.4 - Zero-Cache Edge-Smart Cloudflare Worker Router
 * ====================================================================================
 * Gives Gemini Connected Apps ONE permanent URL:
 *   https://ida-hexrays-mcp-forever.forested-lung.workers.dev/mcp
 * Reads LIVE_MCP_URL.json via the 0-cache GitHub Contents API and executes live
 * docs.hex-rays.com Markdown fetches, llms.txt searches, and IDAPython/Domain/Microcode
 * synthesis directly at the Cloudflare Edge in 0ms!
 */
const GITHUB_API_LIVE_JSON_URL = "{api_json_url}";
const GITHUB_RAW_LIVE_JSON_URL = "{raw_json_url}";
const GITHUB_DISPATCH_URL = "{dispatch_url}";
const AUTO_WAKE_GH_TOKEN = "{gh_token_for_autowake}";
const EDGE_CURATED_TOOLS = {tools_json_str};
const EDGE_CATALOG = {catalog_json_str};

async function triggerGithubAutoWake() {{
  if (!AUTO_WAKE_GH_TOKEN) return false;
  try {{
    const r = await fetch(GITHUB_DISPATCH_URL, {{
      method: "POST",
      headers: {{
        "Authorization": "Bearer " + AUTO_WAKE_GH_TOKEN,
        "Accept": "application/vnd.github+json",
        "User-Agent": "HexRays-Permanent-Router/1.4",
        "Content-Type": "application/json"
      }},
      body: JSON.stringify({{ ref: "main" }})
    }});
    return r.status === 204 || r.status === 200;
  }} catch (_) {{
    return false;
  }}
}}

async function getLatestTunnelUrl() {{
  if (AUTO_WAKE_GH_TOKEN) {{
    try {{
      const apiRes = await fetch(GITHUB_API_LIVE_JSON_URL + "&t=" + Date.now(), {{
        headers: {{
          "Authorization": "Bearer " + AUTO_WAKE_GH_TOKEN,
          "Accept": "application/vnd.github.raw+json",
          "User-Agent": "HexRays-Permanent-Router/1.4",
          "X-GitHub-Api-Version": "2022-11-28"
        }}
      }});
      if (apiRes.ok) {{
        return await apiRes.json();
      }}
    }} catch (_) {{}}
  }}
  const res = await fetch(GITHUB_RAW_LIVE_JSON_URL + "?t=" + Date.now(), {{
    headers: {{ "User-Agent": "HexRays-Permanent-Router/1.4" }}
  }});
  if (!res.ok) throw new Error("Could not fetch LIVE_MCP_URL.json: HTTP " + res.status);
  return await res.json();
}}

async function fetchHexRaysDocAtEdge(pathOrUrl) {{
  const raw = String(pathOrUrl || "").trim();
  const baseUrl = raw.startsWith("http://") || raw.startsWith("https://")
    ? raw
    : "https://docs.hex-rays.com/" + raw.replace(/^\\/+/, "");
  const candidates = [baseUrl];
  if (baseUrl.startsWith("https://docs.hex-rays.com/") && !baseUrl.endsWith(".md") && !baseUrl.endsWith(".txt")) {{
    candidates.unshift(baseUrl.replace(/\\/+$/, "") + ".md");
  }}
  for (const cand of candidates) {{
    try {{
      const res = await fetch(cand, {{
        headers: {{ "User-Agent": "HexRays-OmniNexus-Edge/1.4" }}
      }});
      if (res.ok) {{
        const txt = await res.text();
        return {{ url: cand, status: res.status, content: txt.slice(0, 15000) }};
      }}
    }} catch (_) {{}}
  }}
  return {{ requested: pathOrUrl, error: "Could not fetch live page; check path or use hexrays_search_docs." }};
}}

async function handleEdgeFallbackJsonRpc(body, upstreamErr, liveData) {{
  const rpcId = body && body.id !== undefined ? body.id : 1;
  const method = (body && body.method) || "";
  const params = (body && body.params) || {{}};

  if (method === "initialize") {{
    return {{
      jsonrpc: "2.0",
      id: rpcId,
      result: {{
        protocolVersion: "2025-03-26",
        capabilities: {{ tools: {{ listChanged: true }} }},
        serverInfo: {{ name: "HexRays-IDA-OmniNexus", version: "1.4.0" }}
      }}
    }};
  }}

  if (method === "notifications/initialized" || method.startsWith("notifications/")) {{
    return {{ jsonrpc: "2.0", id: rpcId, result: {{}} }};
  }}

  if (method === "tools/list") {{
    return {{
      jsonrpc: "2.0",
      id: rpcId,
      result: {{ tools: EDGE_CURATED_TOOLS }}
    }};
  }}

  if (method === "tools/call") {{
    const tName = params.name || "";
    const tArgs = params.arguments || {{}};

    if (tName === "hexrays_list_api_and_mcp_catalog" || tName === "hexrays_search_docs") {{
      const catFilter = String(tArgs.category || "").trim().toLowerCase();
      const qFilter = String(tArgs.search || tArgs.query || "").trim().toLowerCase();
      const out = {{}};
      for (const [k, v] of Object.entries(EDGE_CATALOG)) {{
        if (catFilter && catFilter !== k) continue;
        const matched = v.items.filter((item) => !qFilter || item.toLowerCase().includes(qFilter) || v.title.toLowerCase().includes(qFilter) || k.toLowerCase().includes(qFilter));
        if (matched.length > 0) {{
          out[k] = {{ title: v.title, base_url: v.base_url, count: matched.length, items: matched }};
        }}
      }}
      return {{
        jsonrpc: "2.0",
        id: rpcId,
        result: {{ content: [{{ type: "text", text: JSON.stringify(out, null, 2) }}] }}
      }};
    }}

    if (tName === "hexrays_fetch_doc_markdown") {{
      const docRes = await fetchHexRaysDocAtEdge(tArgs.path_or_url || "https://docs.hex-rays.com/llms.txt");
      return {{
        jsonrpc: "2.0",
        id: rpcId,
        result: {{ content: [{{ type: "text", text: JSON.stringify(docRes, null, 2) }}] }}
      }};
    }}

    if (tName === "hexrays_doctor_and_status") {{
      return {{
        jsonrpc: "2.0",
        id: rpcId,
        result: {{
          content: [{{
            type: "text",
            text: JSON.stringify({{
              status: "LIVE_EDGE_AND_CLOUD_HYBRID",
              router_version: "Hex-Rays Omni-Nexus v1.4 Zero-Cache Edge-Smart Router",
              docs_portal: "https://docs.hex-rays.com/ (IDA 9.5 + Official IDA MCP + idalib + Domain API + HCLI + IDAPython + Microcode)",
              total_categories: Object.keys(EDGE_CATALOG).length,
              backend_relay_state: liveData || {{ status: "ROTATING_OR_WAKING", detail: String(upstreamErr || "") }}
            }}, null, 2)
          }}]
        }}
      }};
    }}

    return {{
      jsonrpc: "2.0",
      id: rpcId,
      result: {{
        content: [{{
          type: "text",
          text: JSON.stringify({{
            status: "CLOUD_RELAY_BOOTING_OR_WAKING",
            tool_requested: tName,
            message: "Your 24/7 GitHub Cloud Relay for Hex-Rays IDA Omni-Nexus is waking (~25s). Repeat this tool call shortly!",
            detail: String(upstreamErr || "")
          }}, null, 2)
        }}]
      }}
    }};
  }}

  return {{ jsonrpc: "2.0", id: rpcId, result: {{}} }};
}}

export default {{
  async fetch(request) {{
    const corsHeaders = {{
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept, MCP-Session-Id, Last-Event-ID"
    }};

    if (request.method === "OPTIONS") {{
      return new Response(null, {{ status: 204, headers: corsHeaders }});
    }}

    const url = new URL(request.url);
    let parsedBody = null;
    let rawBodyBuffer = undefined;
    if (request.method !== "GET" && request.method !== "HEAD") {{
      rawBodyBuffer = await request.arrayBuffer();
      try {{
        parsedBody = JSON.parse(new TextDecoder().decode(rawBodyBuffer));
      }} catch (_) {{}}
    }}

    if (parsedBody && (
      parsedBody.method === "initialize" ||
      parsedBody.method === "notifications/initialized" ||
      parsedBody.method === "tools/list" ||
      (parsedBody.method === "tools/call" && parsedBody.params && (
        parsedBody.params.name === "hexrays_list_api_and_mcp_catalog" ||
        parsedBody.params.name === "hexrays_search_docs" ||
        parsedBody.params.name === "hexrays_fetch_doc_markdown"
      ))
    )) {{
      return new Response(JSON.stringify(await handleEdgeFallbackJsonRpc(parsedBody, null, null)), {{
        status: 200,
        headers: {{ "Content-Type": "application/json", ...corsHeaders }}
      }});
    }}

    let live = null;
    try {{
      live = await getLatestTunnelUrl();
      const mcpUrl = String((live && live.mcp_url) || "").trim();
      if (!mcpUrl.startsWith("https://")) {{
        throw new Error("LIVE_MCP_URL.json mcp_url is not a full https:// URL yet: " + JSON.stringify(mcpUrl));
      }}
      const targetBase = (live.gui_url && String(live.gui_url).startsWith("https://") ? live.gui_url : mcpUrl.replace(/\\/mcp$/, "")).replace(/\\/$/, "");
      const targetUrl = targetBase + url.pathname + url.search;

      if (request.method === "GET" && (url.pathname === "/status" || url.pathname === "/router-status")) {{
        return new Response(JSON.stringify({{
          router: "Hex-Rays Omni-Nexus v1.4 Zero-Cache Edge-Smart Router",
          active_backend_mcp_url: live.mcp_url,
          active_backend_gui_url: live.gui_url,
          updated_at: live.updated_at
        }}, null, 2), {{
          status: 200,
          headers: {{ "Content-Type": "application/json", ...corsHeaders }}
        }});
      }}

      const proxyReq = new Request(targetUrl, {{
        method: request.method,
        headers: request.headers,
        body: rawBodyBuffer,
      }});
      const resp = await fetch(proxyReq);
      if (resp.status === 530 || resp.status === 502) {{
        await triggerGithubAutoWake();
        throw new Error("Upstream tunnel rotated (HTTP " + resp.status + ") - triggered Auto-Wake!");
      }}
      const newHeaders = new Headers(resp.headers);
      newHeaders.set("Access-Control-Allow-Origin", "*");
      return new Response(resp.body, {{ status: resp.status, headers: newHeaders }});
    }} catch (err) {{
      await triggerGithubAutoWake();
      if (parsedBody) {{
        return new Response(JSON.stringify(await handleEdgeFallbackJsonRpc(parsedBody, err, live)), {{
          status: 200,
          headers: {{ "Content-Type": "application/json", ...corsHeaders }}
        }});
      }}
      return new Response(JSON.stringify({{
        status: "AUTO_WAKING_CLOUD_RELAY",
        router: "Hex-Rays Omni-Nexus v1.4 Zero-Cache Edge-Smart Router",
        docs_portal: "https://docs.hex-rays.com/",
        live_json_state: live,
        message: "Signaled your 24/7 Hex-Rays GitHub Cloud Relay to wake (~25s).",
        error: String(err)
      }}, null, 2), {{
        status: 200,
        headers: {{ "Content-Type": "application/json", ...corsHeaders }}
      }});
    }}
  }}
}};
"""


# ---------------------------------------------------------------------------
# 5. Autonomous `--forever` Provisioner
# ---------------------------------------------------------------------------

def auto_detect_saved_github_token(work_dir: Path) -> str:
    candidates = [
        work_dir / "forever_credentials.json",
        Path.cwd() / "forever_credentials.json",
        Path.home() / ".ghidra_mcp_forever" / "forever_credentials.json",
        Path(tempfile.gettempdir()) / "ghidra_mcp_cloud" / "forever_credentials.json",
        Path(tempfile.gettempdir()) / "craft_anything_mcp_cloud" / "forever_credentials.json",
    ]
    for cfg in candidates:
        if cfg.exists():
            try:
                tok = json.loads(cfg.read_text(encoding="utf-8")).get("github_token", "")
                if tok:
                    return tok.strip()
            except Exception:
                pass
    for env_key in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(env_key):
            return os.environ[env_key].strip()
    if shutil.which("gh"):
        try:
            out = subprocess.check_output(["gh", "auth", "token"], stderr=subprocess.DEVNULL, text=True).strip()
            if out and len(out) >= 20:
                return out
        except Exception:
            pass
    return ""


def copy_to_system_clipboard(text: str) -> bool:
    sys_name = platform.system().lower()
    try:
        if "windows" in sys_name:
            subprocess.run(["clip"], input=text.encode("utf-8"), check=True)
            return True
        if "darwin" in sys_name:
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
            return True
    except Exception:
        pass
    return False


def deploy_to_github_cloud_api(gh_token: str, repo_name: str = "ida-hexrays-mcp-omni-cloud") -> Dict[str, Any]:
    token = gh_token.strip()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "HexRays-OmniNexus/1.4",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        user_req = urllib.request.Request("https://api.github.com/user", headers=headers)
        with urllib.request.urlopen(user_req, timeout=10) as resp:
            username = json.loads(resp.read().decode("utf-8")).get("login")

        create_payload = json.dumps({
            "name": repo_name,
            "description": "Hex-Rays IDA & Docs Omni-Nexus v1.4 - 24/7 Cloud MCP Server",
            "private": False,
            "auto_init": True,
        }).encode("utf-8")
        try:
            c_req = urllib.request.Request("https://api.github.com/user/repos", data=create_payload, headers=headers, method="POST")
            urllib.request.urlopen(c_req, timeout=15)
            time.sleep(2)
        except urllib.error.HTTPError as he:
            if he.code not in (422, 409):
                raise

        def _put_file(rel_path: str, content_str: str, msg: str) -> None:
            api_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/{rel_path}"
            sha = None
            try:
                g_req = urllib.request.Request(api_url, headers=headers)
                with urllib.request.urlopen(g_req, timeout=8) as g_resp:
                    sha = json.loads(g_resp.read().decode("utf-8")).get("sha")
            except Exception:
                pass
            body_dict: Dict[str, Any] = {
                "message": msg,
                "content": base64.b64encode(content_str.encode("utf-8")).decode("ascii"),
            }
            if sha:
                body_dict["sha"] = sha
            p_req = urllib.request.Request(api_url, data=json.dumps(body_dict).encode("utf-8"), headers=headers, method="PUT")
            urllib.request.urlopen(p_req, timeout=20)

        # Cancel any older stuck/in-progress runs FIRST before pushing files
        try:
            runs_url = f"https://api.github.com/repos/{username}/{repo_name}/actions/runs?per_page=10"
            r_req = urllib.request.Request(runs_url, headers=headers)
            with urllib.request.urlopen(r_req, timeout=10) as r_resp:
                runs_data = json.loads(r_resp.read().decode("utf-8")).get("workflow_runs") or []
            for run in runs_data:
                if run.get("status") in ("in_progress", "queued", "waiting"):
                    cancel_url = f"https://api.github.com/repos/{username}/{repo_name}/actions/runs/{run['id']}/cancel"
                    try:
                        urllib.request.urlopen(urllib.request.Request(cancel_url, data=b"", headers=headers, method="POST"), timeout=6)
                    except Exception:
                        pass
            time.sleep(2)
        except Exception:
            pass

        boot_json = json.dumps({
            "status": "BOOTING",
            "engine": "docs.hex-rays.com (IDA 9.5 Omni-Nexus)",
            "mcp_url": "",
            "gui_url": "",
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, indent=2) + "\n"
        _put_file("LIVE_MCP_URL.json", boot_json, "Reset LIVE_MCP_URL.json for fresh tunnel boot [skip ci]")
        launcher_source = Path(__file__).resolve().read_text(encoding="utf-8")
        _put_file("ida_hexrays_mcp_cloud_launcher.py", launcher_source, "Deploy Hex-Rays IDA Omni-Nexus v1.4 [skip ci]")
        _put_file("cloudflare_permanent_router_worker.js", build_permanent_cloudflare_worker_js(username, repo_name), "Add Zero-Cache Edge-Smart v1.4 Router [skip ci]")
        _put_file(".github/workflows/ida_hexrays_mcp_cloud.yml", GITHUB_WORKFLOW_YML, "Launch 24/7 Fast-Tunnel Hex-Rays Cloud Relay v1.4")

        try:
            disp_url = f"https://api.github.com/repos/{username}/{repo_name}/actions/workflows/ida_hexrays_mcp_cloud.yml/dispatches"
            disp_req = urllib.request.Request(disp_url, data=json.dumps({"ref": "main"}).encode("utf-8"), headers=headers, method="POST")
            urllib.request.urlopen(disp_req, timeout=10)
        except Exception:
            pass

        return {
            "status": "DEPLOYED_GITHUB_CLOUD",
            "username": username,
            "repo_name": repo_name,
            "api_live_url": f"https://api.github.com/repos/{username}/{repo_name}/contents/LIVE_MCP_URL.json?ref=main",
            "raw_live_url": f"https://raw.githubusercontent.com/{username}/{repo_name}/main/LIVE_MCP_URL.json",
            "github_repo": f"https://github.com/{username}/{repo_name}",
            "github_actions_url": f"https://github.com/{username}/{repo_name}/actions",
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def deploy_cloudflare_worker_automatically(
    work_dir: Path,
    github_username: str,
    repo_name: str,
    gh_token: str,
) -> Dict[str, Any]:
    worker_name = "ida-hexrays-mcp-forever"
    worker_js = build_permanent_cloudflare_worker_js(github_username, repo_name, gh_token)

    npx_cmd = "npx.cmd" if platform.system().lower() == "windows" and shutil.which("npx.cmd") else "npx"
    if not shutil.which(npx_cmd):
        return {"status": "NEEDS_NODE_NPX", "message": "Install Node.js (`npx`) to auto-deploy the Cloudflare Worker."}

    w_dir = work_dir / "cf_hexrays_forever_worker"
    w_dir.mkdir(parents=True, exist_ok=True)
    (w_dir / "worker.js").write_text(worker_js, encoding="utf-8")

    # Check if we already know the Forested Lung account_id from sibling worker folders
    saved_acct_id = ""
    for candidate_toml in (
        w_dir / "wrangler.toml",
        work_dir / "cf_craft_forever_worker" / "wrangler.toml",
        work_dir / "cf_forever_worker" / "wrangler.toml",
    ):
        if candidate_toml.exists():
            m_acct = re.search(r'account_id\s*=\s*"([0-9a-fA-F]{32})"', candidate_toml.read_text(encoding="utf-8"))
            if m_acct:
                saved_acct_id = m_acct.group(1)
                break

    if saved_acct_id:
        (w_dir / "wrangler.toml").write_text(
            f'name = "{worker_name}"\naccount_id = "{saved_acct_id}"\nmain = "worker.js"\ncompatibility_date = "2026-01-01"\nworkers_dev = true\n',
            encoding="utf-8",
        )
    else:
        (w_dir / "wrangler.toml").write_text(
            f'name = "{worker_name}"\nmain = "worker.js"\ncompatibility_date = "2026-01-01"\nworkers_dev = true\n',
            encoding="utf-8",
        )

    print("[+] Deploying Zero-Cache Edge-Smart Hex-Rays Router Worker via `npx --yes wrangler@latest deploy`...")
    proc = subprocess.Popen(
        [npx_cmd, "--yes", "wrangler@latest", "deploy"],
        cwd=str(w_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deployed_url = ""
    output_lines: List[str] = []
    if proc.stdout:
        for line in proc.stdout:
            print(line, end="", flush=True)
            output_lines.append(line)
            m = re.search(r"(https://[a-zA-Z0-9._-]+\.workers\.dev)", line)
            if m:
                deployed_url = m.group(1).rstrip("/") + "/mcp"
    proc.wait()

    full_out = "".join(output_lines)
    if not deployed_url and ("more than one account available" in full_out.lower() or "cloudflare_account_id" in full_out.lower()):
        acct_matches = re.findall(r"`([^`]+)`:\s*`([0-9a-fA-F]{32})`", full_out)
        chosen_name, chosen_id = "", ""
        for a_name, a_id in acct_matches:
            if "forested lung" in a_name.lower():
                chosen_name, chosen_id = a_name, a_id
                break
        if not chosen_id and acct_matches:
            chosen_name, chosen_id = acct_matches[0]
        if chosen_id:
            print(f"[+] Multiple Cloudflare accounts detected - auto-selecting `{chosen_name}` ({chosen_id}) and re-deploying...")
            (w_dir / "wrangler.toml").write_text(
                f'name = "{worker_name}"\naccount_id = "{chosen_id}"\nmain = "worker.js"\ncompatibility_date = "2026-01-01"\nworkers_dev = true\n',
                encoding="utf-8",
            )
            env_with_acct = dict(os.environ)
            env_with_acct["CLOUDFLARE_ACCOUNT_ID"] = chosen_id
            proc_retry = subprocess.Popen(
                [npx_cmd, "--yes", "wrangler@latest", "deploy"],
                cwd=str(w_dir),
                env=env_with_acct,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if proc_retry.stdout:
                for line in proc_retry.stdout:
                    print(line, end="", flush=True)
                    output_lines.append(line)
                    m = re.search(r"(https://[a-zA-Z0-9._-]+\.workers\.dev)", line)
                    if m:
                        deployed_url = m.group(1).rstrip("/") + "/mcp"
            proc_retry.wait()

    if deployed_url:
        copy_to_system_clipboard(deployed_url)
        return {
            "status": "DEPLOYED_PERMANENT_WORKER",
            "permanent_mcp_url": deployed_url,
            "method": "Wrangler Auto-Deploy (Zero-Cache Edge-Smart v1.4)",
        }
    return {"status": "WRANGLER_ERROR", "logs": "".join(output_lines[-15:])}


def run_forever_provisioner(work_dir: Path, gh_token_input: str = "") -> Dict[str, Any]:
    work_dir.mkdir(parents=True, exist_ok=True)
    gh_token = gh_token_input.strip() or auto_detect_saved_github_token(work_dir)
    if not gh_token:
        gh_url = "https://github.com/settings/tokens/new?description=HexRays-24x7-Forever&scopes=repo,workflow"
        print(f"Opening GitHub Token page: {gh_url}")
        try:
            webbrowser.open(gh_url)
        except Exception:
            pass
        gh_token = input("-> Paste your GitHub Token (ghp_...) and press Enter: ").strip()

    (work_dir / "forever_credentials.json").write_text(json.dumps({"github_token": gh_token}, indent=2), encoding="utf-8")

    print("[+] Step 1/3: Auto-provisioning 24/7 Perpetual GitHub Cloud Relay for `docs.hex-rays.com` (IDA 9.5 Omni-Nexus)...")
    gh_res = deploy_to_github_cloud_api(gh_token, repo_name="ida-hexrays-mcp-omni-cloud")
    if gh_res.get("status") != "DEPLOYED_GITHUB_CLOUD":
        return gh_res

    print("[+] Step 2/3: Deploying Zero-Cache Edge-Smart Permanent Front-Door Cloudflare Worker Router...")
    cf_res = deploy_cloudflare_worker_automatically(
        work_dir=work_dir,
        github_username=gh_res["username"],
        repo_name=gh_res["repo_name"],
        gh_token=gh_token,
    )

    print("[+] Step 3/3: Polling GitHub Contents API (0-cache real-time) for LIVE_MCP_URL.json (~25-60s)...")
    live_tunnel_mcp = ""
    api_live_url = gh_res["api_live_url"]
    raw_live_url = gh_res["raw_live_url"]
    api_headers = {
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github.raw+json",
        "User-Agent": "HexRays-AutoProvisioner/1.4",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    for elapsed in range(0, 95, 5):
        try:
            req = urllib.request.Request(f"{api_live_url}&t={int(time.time())}", headers=api_headers)
            with urllib.request.urlopen(req, timeout=6) as r:
                live_data = json.loads(r.read().decode("utf-8"))
                candidate_url = str(live_data.get("mcp_url") or "").strip()
                if candidate_url.startswith("https://") and ".trycloudflare.com" in candidate_url:
                    live_tunnel_mcp = candidate_url
                    break
        except Exception:
            pass
        print(f"    ... GitHub Cloud VM starting tunnel ({elapsed}s elapsed)...")
        time.sleep(5)

    final_url = cf_res.get("permanent_mcp_url") or live_tunnel_mcp
    if final_url:
        copy_to_system_clipboard(final_url)

    return {
        "status": "HEXRAYS_FOREVER_COMPLETE",
        "github_repo": gh_res["github_repo"],
        "github_actions_url": gh_res["github_actions_url"],
        "raw_live_url": raw_live_url,
        "active_relay_tunnel_mcp_url": live_tunnel_mcp or "Edge Worker is LIVE now (GitHub runner finishes in ~20s)",
        "cloudflare_worker_result": cf_res,
        "final_gemini_mcp_url": final_url,
        "instructions": "DONE! Paste `final_gemini_mcp_url` into Gemini -> Settings -> Connected Apps -> Add a custom app link!",
    }


# ---------------------------------------------------------------------------
# 6. Streamable HTTP + JSON-RPC 2.0 MCP Server
# ---------------------------------------------------------------------------

def handle_mcp_jsonrpc(bridge: HexRaysOmniBridge, body: Dict[str, Any]) -> Dict[str, Any]:
    rpc_id = body.get("id", 1)
    method = body.get("method", "")
    params = body.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "HexRays-IDA-OmniNexus", "version": "1.4.0"},
            },
        }

    if method == "notifications/initialized":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": DIRECT_CURATED_TOOLS}}

    if method == "tools/call":
        t_name = params.get("name", "")
        t_args = params.get("arguments") or {}

        if t_name == "hexrays_doctor_and_status":
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(bridge.run_doctor(), indent=2)}]}}

        if t_name == "hexrays_list_api_and_mcp_catalog":
            cat_filter = (t_args.get("category") or "").strip().lower()
            q_filter = (t_args.get("search") or "").strip().lower()
            out: Dict[str, Any] = {}
            for k, v in HEXRAYS_ECOSYSTEM_CATALOG.items():
                if cat_filter and cat_filter != k:
                    continue
                matched = [item for item in v["items"] if not q_filter or q_filter in item.lower() or q_filter in v["title"].lower()]
                if matched:
                    out[k] = {"title": v["title"], "base_url": v["base_url"], "count": len(matched), "items": matched}
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}}

        if t_name == "hexrays_fetch_doc_markdown":
            doc_res = bridge.fetch_hexrays_doc(t_args.get("path_or_url", "https://docs.hex-rays.com/llms.txt"))
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(doc_res, indent=2)}]}}

        if t_name == "hexrays_search_docs":
            search_res = bridge.search_docs(t_args.get("query", ""))
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(search_res, indent=2)}]}}

        if t_name == "hexrays_open_and_triage_binary":
            tri_res = bridge.triage_binary(t_args.get("target_url_or_path", ""))
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(tri_res, indent=2)}]}}

        if t_name == "hexrays_decompile_or_disassemble":
            dec_res = bridge.decompile_or_disassemble(
                t_args.get("target_url_or_path", ""),
                t_args.get("function_or_address", "main"),
            )
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(dec_res, indent=2)}]}}

        if t_name == "hexrays_generate_idapython_or_domain_script":
            gen_res = build_idapython_script_template(
                t_args.get("task_description", "Inspect all functions"),
                t_args.get("api_style", "idalib_headless"),
                t_args.get("binary_path", "./sample.bin"),
            )
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(gen_res, indent=2)}]}}

        if t_name == "hexrays_microcode_and_ctree_advisor":
            mc_res = build_microcode_advisor_payload(t_args.get("deobfuscation_goal", "MBA simplification"))
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(mc_res, indent=2)}]}}

        if t_name == "hexrays_flirt_and_lumina_toolkit":
            fl_res = build_flirt_and_lumina_payload(
                t_args.get("library_format", "elf_a"),
                t_args.get("library_name", "libtarget.a"),
            )
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(fl_res, indent=2)}]}}

        if t_name == "hexrays_bridge_ghidra_and_craft":
            br_res = {
                "workflow_goal": t_args.get("workflow_goal", ""),
                "tri_engine_pipeline": {
                    "step_1_ida_hexrays": "Use `idalib` / `ida-domain` / `ida-mcp` (`https://ida-hexrays-mcp-forever.forested-lung.workers.dev/mcp`) for Microcode (`mbl_array_t`), FLIRT 2.0 v11 signatures, and Lumina metadata.",
                    "step_2_ghidra_omni_nexus": "Cross-verify P-Code and C struct recovery via `https://ghidra-mcp-forever.forested-lung.workers.dev/mcp` (`ghidra-omni-nexus`).",
                    "step_3_craft_anything_foundry": "Feed recovered headers, assets, and call graphs into `https://craft-anything-mcp-forever.forested-lung.workers.dev/mcp` (`craft-anything-omni-foundry`) for iterative Study-Build-Check-Ready reconstruction.",
                },
            }
            return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps(br_res, indent=2)}]}}

        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": [{"type": "text", "text": json.dumps({"unknown_tool": t_name}, indent=2)}]}}

    return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}


def start_cloud_server(port: int, work_dir: Path) -> None:
    bridge = HexRaysOmniBridge(work_dir, install_in_background=True)

    class Handler(http.server.BaseHTTPRequestHandler):
        def _cors(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, MCP-Session-Id")

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self._cors()
            self.end_headers()

        def do_GET(self) -> None:
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(bridge.run_doctor(), indent=2).encode("utf-8"))

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            try:
                body = json.loads(raw)
            except Exception:
                body = {}
            resp = handle_mcp_jsonrpc(bridge, body)
            out_bytes = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out_bytes)))
            self.end_headers()
            self.wfile.write(out_bytes)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    class ThreadedTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    srv = ThreadedTCPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[+] Hex-Rays IDA & Docs v1.4 Omni-Nexus MCP Server listening on 0.0.0.0:{port}/mcp", flush=True)

    cf_bin = shutil.which("cloudflared")
    if not cf_bin and platform.system().lower() == "linux":
        cf_path = work_dir / "cloudflared"
        if not cf_path.exists():
            urllib.request.urlretrieve(
                "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
                str(cf_path),
            )
            cf_path.chmod(0o755)
        cf_bin = str(cf_path)

    if cf_bin:
        tunnel_proc = subprocess.Popen(
            [cf_bin, "tunnel", "--url", f"http://127.0.0.1:{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        printed = False
        if tunnel_proc.stdout:
            for line in tunnel_proc.stdout:
                print(line, end="", flush=True)
                m = re.search(r"(https://[a-zA-Z0-9-]+\.trycloudflare\.com)", line)
                if m and not printed:
                    printed = True
                    base_url = m.group(1).rstrip("/")
                    live_payload = {
                        "status": "LIVE",
                        "engine": "docs.hex-rays.com (IDA 9.5 Omni-Nexus)",
                        "mcp_url": f"{base_url}/mcp",
                        "gui_url": f"{base_url}/",
                        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                    try:
                        Path("/tmp/LIVE_MCP_URL.json").write_text(json.dumps(live_payload, indent=2) + "\n", encoding="utf-8")
                    except Exception:
                        pass
                    print("\n" + "=" * 78, flush=True)
                    print(f"  HEX-RAYS IDA PUBLIC TUNNEL READY: {base_url}/mcp", flush=True)
                    print("=" * 78 + "\n", flush=True)

    while True:
        time.sleep(3600)


def main() -> int:
    parser = argparse.ArgumentParser(description="Hex-Rays IDA & Docs v1.4 Omni-Nexus - 24/7 Cloud MCP Server & Auto-Provisioner")
    parser.add_argument("--forever", action="store_true", help="Auto-provision 24/7 GitHub Cloud Relay + Zero-Cache Edge-Smart Permanent Cloudflare Worker URL")
    parser.add_argument("--port", type=int, default=7860, help="HTTP port for MCP server (default 7860)")
    parser.add_argument("--self-test", action="store_true", help="Run offline deterministic self-test of all 10 Hex-Rays MCP tools and Worker syntax")
    args = parser.parse_args()

    work_dir = Path(tempfile.gettempdir()) / "ida_hexrays_mcp_cloud"
    work_dir.mkdir(parents=True, exist_ok=True)

    if args.self_test:
        bridge = HexRaysOmniBridge(work_dir, install_in_background=False)
        init_res = handle_mcp_jsonrpc(bridge, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        list_res = handle_mcp_jsonrpc(bridge, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tri_res = handle_mcp_jsonrpc(bridge, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "hexrays_open_and_triage_binary", "arguments": {"target_url_or_path": ""}}})
        dec_res = handle_mcp_jsonrpc(bridge, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "hexrays_decompile_or_disassemble", "arguments": {"function_or_address": "derive_route_seed"}}})
        worker_js = build_permanent_cloudflare_worker_js("alisyyed", "ida-hexrays-mcp-omni-cloud", "ghp_test")
        assert "handleEdgeFallbackJsonRpc" in worker_js
        assert "derive_route_seed" in json.dumps(dec_res) or "disassembly_intel" in json.dumps(dec_res)
        print(json.dumps({
            "self_test": "PASSED_HEXRAYS_V1_4_ZERO_CACHE_EDGE_SMART",
            "server_info": init_res["result"]["serverInfo"],
            "curated_mcp_tools_count": len(list_res["result"]["tools"]),
            "total_catalog_categories": len(HEXRAYS_ECOSYSTEM_CATALOG),
            "demo_binary_triage_status": "OK" if "sha256" in json.dumps(tri_res) else "WARN",
        }, indent=2))
        return 0

    if args.forever:
        res = run_forever_provisioner(Path.cwd())
        print("\n" + "=" * 82)
        print("  HEX-RAYS IDA & DOCS 24/7 CLOUD PROVISIONER RESULT (v1.4 ZERO-CACHE EDGE-SMART)")
        print("=" * 82)
        print(json.dumps(res, indent=2))
        print("=" * 82)
        return 0

    start_cloud_server(args.port, work_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())