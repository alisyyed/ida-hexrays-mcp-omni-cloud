/**
 * Hex-Rays IDA & Docs Omni-Nexus v1.4 - Zero-Cache Edge-Smart Cloudflare Worker Router
 * ====================================================================================
 * Gives Gemini Connected Apps ONE permanent URL:
 *   https://ida-hexrays-mcp-forever.forested-lung.workers.dev/mcp
 * Reads LIVE_MCP_URL.json via the 0-cache GitHub Contents API and executes live
 * docs.hex-rays.com Markdown fetches, llms.txt searches, and IDAPython/Domain/Microcode
 * synthesis directly at the Cloudflare Edge in 0ms!
 */
const GITHUB_API_LIVE_JSON_URL = "https://api.github.com/repos/alisyyed/ida-hexrays-mcp-omni-cloud/contents/LIVE_MCP_URL.json?ref=main";
const GITHUB_RAW_LIVE_JSON_URL = "https://raw.githubusercontent.com/alisyyed/ida-hexrays-mcp-omni-cloud/main/LIVE_MCP_URL.json";
const GITHUB_DISPATCH_URL = "https://api.github.com/repos/alisyyed/ida-hexrays-mcp-omni-cloud/actions/workflows/ida_hexrays_mcp_cloud.yml/dispatches";
const AUTO_WAKE_GH_TOKEN = "";
const EDGE_CURATED_TOOLS = [{"name": "hexrays_doctor_and_status", "description": "[Hex-Rays IDA Omni-Nexus] Check health of the 24/7 Hex-Rays Cloud MCP Relay, Zero-Cache Edge Router, installed tools (`ida-hcli`, `ida-domain`, `ida-mcp`, `idalib`, `rizin`, `objdump`), and active documentation portals (`docs.hex-rays.com`).", "inputSchema": {"type": "object", "properties": {}}}, {"name": "hexrays_list_api_and_mcp_catalog", "description": "[Hex-Rays IDA Omni-Nexus] Browse or search the complete Hex-Rays IDA 9.5 ecosystem catalog (`docs_portal`, `ida_mcp_official`, `ida_domain_api`, `idapython_sdk`, `cpp_microcode_sdk`, `hcli_and_cicd`).", "inputSchema": {"type": "object", "properties": {"category": {"type": "string", "description": "Optional category filter (`docs_portal`, `ida_mcp_official`, `ida_domain_api`, `idapython_sdk`, `cpp_microcode_sdk`, `hcli_and_cicd`)."}, "search": {"type": "string", "description": "Optional keyword substring to filter items."}}}}, {"name": "hexrays_fetch_doc_markdown", "description": "[Hex-Rays IDA Omni-Nexus] Fetch live documentation or `llms.txt` directly from `https://docs.hex-rays.com/`, `https://ida-domain.docs.hex-rays.com/`, `https://python.docs.hex-rays.com/`, `https://cpp.docs.hex-rays.com/`, or `https://hcli.docs.hex-rays.com/` as clean Markdown.", "inputSchema": {"type": "object", "properties": {"path_or_url": {"type": "string", "description": "Full Hex-Rays docs URL or relative path (e.g. 'core/idalib', 'add-ons/mcp', 'release-notes/9_5', 'llms.txt', 'https://ida-domain.docs.hex-rays.com/usage/')."}}, "required": ["path_or_url"]}}, {"name": "hexrays_search_docs", "description": "[Hex-Rays IDA Omni-Nexus] Search the official Hex-Rays `llms.txt` index and curated IDA 9.5 / IDAPython / `idalib` / `ida-domain` / `IDA MCP` / Microcode documentation pages by keyword.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "Search query (e.g. 'idalib', 'multiplexing', 'microcode', 'flirt 2.0', 'lumina', 'domain api', 'hcli')."}}, "required": ["query"]}}, {"name": "hexrays_open_and_triage_binary", "description": "[Hex-Rays IDA Omni-Nexus] Triage an ELF, PE/EXE/DLL/SYS, Mach-O, or WASM binary by URL or path using IDA-compatible metadata (format, architecture, SHA-256, Shannon entropy, segments, imports, exports, strings, and `idalib` / `ida-mcp` session status).", "inputSchema": {"type": "object", "properties": {"target_url_or_path": {"type": "string", "description": "HTTPS URL or local path of the binary to inspect."}}, "required": ["target_url_or_path"]}}, {"name": "hexrays_decompile_or_disassemble", "description": "[Hex-Rays IDA Omni-Nexus] Disassemble or decompile a function/symbol/address in a target binary via `idalib` / `ida-mcp` (if an IDA engine is attached) or the built-in cloud disassembler/pseudocode lifter (`objdump` / `rizin` / ELF-PE analyzer).", "inputSchema": {"type": "object", "properties": {"target_url_or_path": {"type": "string", "description": "Target binary path or HTTPS URL (defaults to active sample if omitted)."}, "function_or_address": {"type": "string", "description": "Function name (e.g. 'main', 'entry') or hex address (e.g. '0x140001000')."}}, "required": ["function_or_address"]}}, {"name": "hexrays_generate_idapython_or_domain_script", "description": "[Hex-Rays IDA Omni-Nexus] Generate a complete, ready-to-run IDA 9.5 script using headless `idalib` (`import idapro`), the Pythonic `ida_domain` API (`from ida_domain import Database`), or classic `ida_hexrays` / `idautils` for any reverse-engineering task.", "inputSchema": {"type": "object", "properties": {"task_description": {"type": "string", "description": "What the script should accomplish (e.g. 'batch decompile all functions calling CryptEncrypt', 'extract vtables and apply C structs', 'scan for XOR loops in microcode')."}, "api_style": {"type": "string", "description": "Preferred API style: 'idalib_headless' (default), 'ida_domain', 'idapython_hexrays', or 'ida_mcp_client'."}, "binary_path": {"type": "string", "description": "Optional target binary path to pre-fill in the generated script."}}, "required": ["task_description"]}}, {"name": "hexrays_microcode_and_ctree_advisor", "description": "[Hex-Rays IDA Omni-Nexus] Provide exact Hex-Rays Decompiler Microcode (`mbl_array_t`, `minsn_t`, `mop_t`, `optinsn_t`, `optblock_t`, maturity levels `MMAT_*`) and C-tree AST (`cfunc_t`, `ctree_visitor_t`) architecture + C++/IDAPython code for deobfuscation or custom optimization.", "inputSchema": {"type": "object", "properties": {"deobfuscation_goal": {"type": "string", "description": "Obfuscation pattern or optimization goal (e.g. 'opaque predicates', 'control-flow flattening', 'mixed boolean-arithmetic MBA', 'custom call convention', 'indirect jump resolution')."}}, "required": ["deobfuscation_goal"]}}, {"name": "hexrays_flirt_and_lumina_toolkit", "description": "[Hex-Rays IDA Omni-Nexus] Generate FLIRT 2.0 (v11 reference-driven naming) `.pat`/`.sig` build pipelines (`pelf`/`pcf`/`pcoff` + `sigmake`) and private `lumina-client` (port 7443) commands.", "inputSchema": {"type": "object", "properties": {"library_format": {"type": "string", "description": "Library type ('elf_a', 'pe_lib', 'macho_a', 'idb_makesig', or 'lumina_private')."}, "library_name": {"type": "string", "description": "Name of the static library or target binary (e.g. 'libssl.a', 'libSceAgcDriver.a')."}}, "required": ["library_format"]}}, {"name": "hexrays_bridge_ghidra_and_craft", "description": "[Hex-Rays IDA Omni-Nexus] Cross-map addresses, function prototypes, C structs, and workflows between Hex-Rays IDA (`idalib` / `ida-mcp`), Ghidra 12.1.4 (`ghidra-omni-nexus`), Craft-Anything (`craft-anything-omni-foundry`), and AnyPS5 (`anyps5`).", "inputSchema": {"type": "object", "properties": {"workflow_goal": {"type": "string", "description": "Cross-engine goal (e.g. 'sync Ghidra decompilation and IDA Microcode on PS5 SELF', 'export IDA types to Craft-Anything deep-mode rebuild')."}}, "required": ["workflow_goal"]}}];
const EDGE_CATALOG = {"docs_portal": {"title": "Hex-Rays IDA 9.5 Main Documentation Portal (docs.hex-rays.com)", "base_url": "https://docs.hex-rays.com", "llms_txt": "https://docs.hex-rays.com/llms.txt", "items": ["https://docs.hex-rays.com/", "https://docs.hex-rays.com/release-notes/9_5", "https://docs.hex-rays.com/release-notes/9_4", "https://docs.hex-rays.com/release-notes/9_0", "https://docs.hex-rays.com/core/idalib", "https://docs.hex-rays.com/core/idalib/overview", "https://docs.hex-rays.com/core/idalib/getting-started", "https://docs.hex-rays.com/core/idalib/how-tos/malware-analysis-with-idalib", "https://docs.hex-rays.com/add-ons/mcp", "https://docs.hex-rays.com/add-ons/mcp/getting-started", "https://docs.hex-rays.com/add-ons/mcp/concepts/multiplexing", "https://docs.hex-rays.com/add-ons/mcp/concepts/where-mcp-fits", "https://docs.hex-rays.com/add-ons/mcp/how-tos/solving-a-multi-binary-challenge-with-ida-mcp", "https://docs.hex-rays.com/core/decompiler/how-tos/microcode-view", "https://docs.hex-rays.com/core/flirt", "https://docs.hex-rays.com/core/flirt/concepts/flirt-2.0", "https://docs.hex-rays.com/core/flirt/how-tos/generate-flirt-signatures-from-libraries", "https://docs.hex-rays.com/add-ons/lumina/reference/lumina-client", "https://docs.hex-rays.com/add-ons/malware", "https://docs.hex-rays.com/developer/idapython", "https://docs.hex-rays.com/developer/idapython/idapython-getting-started", "https://docs.hex-rays.com/developer/idapython/idapython-examples"]}, "ida_mcp_official": {"title": "Official Hex-Rays IDA MCP Server (HexRaysSA/ida-mcp & ida-nexus)", "base_url": "https://github.com/HexRaysSA/ida-mcp", "install_cmd": "uvx ida-hcli mcp install", "http_cmd": "uvx ida-mcp http --host 127.0.0.1 --port 8737", "stdio_cmd": "uvx --exclude-newer=1s ida-mcp stdio --agent=gemini-555", "items": ["open_database", "close_database", "list_databases", "lookup_funcs", "list_funcs", "decompile", "disasm", "imports", "exports", "strings", "xrefs_to", "xrefs_from", "callees", "callers", "rename_func", "rename_lvar", "rename_global", "set_type", "set_comment", "read_bytes", "patch_bytes", "list_structs", "get_stack_frame", "int_convert", "py_eval"]}, "ida_domain_api": {"title": "Hex-Rays IDA Domain API (ida-domain.docs.hex-rays.com)", "base_url": "https://ida-domain.docs.hex-rays.com", "llms_txt": "https://ida-domain.docs.hex-rays.com/llm/llms.txt", "repo_url": "https://github.com/HexRaysSA/ida-domain", "install_cmd": "pip install ida-domain", "items": ["Database (Main IDB/I64 lifecycle and headless opening)", "Entries (Entry point enumeration and ordinals)", "Segments (Memory segment permissions, ranges, and classes)", "Functions (Function discovery, prototypes, flags, and stack frames)", "Flowchart (Basic blocks, CFG edges, predecessors, and successors)", "Instructions (Decoded instructions, mnemonics, and prefixes)", "Operands (Register, immediate, memory, and displacement operands)", "Bytes (Raw byte reads, patching, patterns, and data definitions)", "Strings (ASCII/UTF-16/Swift/Go/Rust string extraction)", "Types (C type parsing, TIL management, structs, and enums)", "Heads (Defined code/data item iteration across EA ranges)", "Hooks (IDP, IDB, UI, and Hex-Rays decompiler event hooks)", "XRefs (Code and data cross-references to/from any EA or struct field)", "Names (Demangled symbols, labels, and verbatim names)", "Comments (Regular, repeatable, anterior/posterior, and ctree pseudocode comments)", "Signature Files (FLIRT v11 .sig application and FLAIR .pat generation)"]}, "idapython_sdk": {"title": "IDAPython SDK 50+ Modules Reference (python.docs.hex-rays.com)", "base_url": "https://python.docs.hex-rays.com", "items": ["idapro (Headless idalib initialization: import idapro; idapro.open_database(...))", "ida_hexrays (Decompiler cfunc_t, ctree_visitor_t, mbl_array_t, minsn_t, mop_t)", "ida_bytes (get_bytes, patch_bytes, create_data, bin_search)", "ida_funcs (func_t, get_func, add_func, get_func_name)", "ida_typeinf (tinfo_t, parse_decl, apply_tinfo, udt_type_data_t)", "ida_kernwin (UI subviews, BWN_MICROCODE, action_handler_t, choose)", "ida_xref (xrefblk_t, add_cref, add_dref, get_first_cref_to)", "ida_segment (segment_t, getseg, get_segm_by_name, add_segm)", "ida_name (get_name, set_name, demangle_name, SN_NOWARN)", "ida_frame (get_frame, define_stkvar, build_stkvar_xrefs)", "ida_ua (insn_t, op_t, decode_insn, print_insn_mnem)", "ida_idp (ph, processor_t, IDP_Hooks, custom instructions)", "ida_nalt (get_input_file_path, retrieve_input_file_sha256, switch_info_t)", "ida_gdl (FlowChart, qflow_chart_t, BasicBlock)", "ida_auto (auto_wait, plan_and_wait, auto_is_ok)", "ida_dbg (Appcall, start_process, wait_for_next_event, get_reg_val)", "ida_loader (file_to_database, mem2base, load_plugin)", "ida_dirtree (dirtree_t, function/type/import folders)", "idautils (Functions, Heads, XrefsTo, XrefsFrom, Strings, Names, Segments)", "idc (High-level legacy compatibility helpers)"]}, "cpp_microcode_sdk": {"title": "Hex-Rays C++ SDK & Microcode VM (cpp.docs.hex-rays.com)", "base_url": "https://cpp.docs.hex-rays.com/vmpage.html", "repo_url": "https://github.com/HexRaysSA/ida-sdk", "items": ["mba_maturity_t (MMAT_GENERATED, MMAT_PREOPTIMIZED, MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2, MMAT_GLBOPT3, MMAT_LVARS)", "mbl_array_t (Microblock array representing a function at a given maturity)", "mblock_t (Single basic block of microinstructions with predset/succset)", "minsn_t (Microinstruction with opcode mcode_t and operands l, r, d)", "mop_t (Micro-operand: mop_r register, mop_n number, mop_d nested insn, mop_S stack, mop_v global, mop_l lvar)", "mlist_t (Interval set of microregisters rlist_t + memory locations ivlset_t)", "optinsn_t (Custom microinstruction optimizer callback)", "optblock_t (Custom microblock optimizer callback)", "cfunc_t (Decompiled function AST root with cinsn_t statement tree and cexpr_t expression tree)", "ctree_visitor_t (AST visitor for inspecting or mutating C-tree before pseudocode rendering)"]}, "hcli_and_cicd": {"title": "Hex-Rays HCLI & GitHub Actions Automation (hcli.docs.hex-rays.com)", "base_url": "https://hcli.docs.hex-rays.com", "repo_url": "https://github.com/HexRaysSA/ida-hcli", "actions_repo": "https://github.com/HexRaysSA/ida-hcli-actions", "items": ["uvx ida-hcli mcp install (Install Official Hex-Rays IDA MCP Server + GUI plugin)", "hcli ida install (Download and install IDA headlessly in CI/Docker)", "hcli ida set-default /path/to/ida (Register default IDA installation for HCLI)", "hcli ida python explain-environment (Trace IDADIR, IDAUSR, and Python venv resolution)", "hcli ida python doctor (Verify IDA Python environment and plugin dependencies)", "hcli plugin install ida-mcp@https://github.com/HexRaysSA/ida-mcp (Install IDA MCP plugin)", "hcli extension upgrade hexrays/malware-analysis (Upgrade IDA 9.5 decoupled add-ons)"]}};

async function triggerGithubAutoWake() {
  if (!AUTO_WAKE_GH_TOKEN) return false;
  try {
    const r = await fetch(GITHUB_DISPATCH_URL, {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + AUTO_WAKE_GH_TOKEN,
        "Accept": "application/vnd.github+json",
        "User-Agent": "HexRays-Permanent-Router/1.4",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ ref: "main" })
    });
    return r.status === 204 || r.status === 200;
  } catch (_) {
    return false;
  }
}

async function getLatestTunnelUrl() {
  if (AUTO_WAKE_GH_TOKEN) {
    try {
      const apiRes = await fetch(GITHUB_API_LIVE_JSON_URL + "&t=" + Date.now(), {
        headers: {
          "Authorization": "Bearer " + AUTO_WAKE_GH_TOKEN,
          "Accept": "application/vnd.github.raw+json",
          "User-Agent": "HexRays-Permanent-Router/1.4",
          "X-GitHub-Api-Version": "2022-11-28"
        }
      });
      if (apiRes.ok) {
        return await apiRes.json();
      }
    } catch (_) {}
  }
  const res = await fetch(GITHUB_RAW_LIVE_JSON_URL + "?t=" + Date.now(), {
    headers: { "User-Agent": "HexRays-Permanent-Router/1.4" }
  });
  if (!res.ok) throw new Error("Could not fetch LIVE_MCP_URL.json: HTTP " + res.status);
  return await res.json();
}

async function fetchHexRaysDocAtEdge(pathOrUrl) {
  const raw = String(pathOrUrl || "").trim();
  const baseUrl = raw.startsWith("http://") || raw.startsWith("https://")
    ? raw
    : "https://docs.hex-rays.com/" + raw.replace(/^\/+/, "");
  const candidates = [baseUrl];
  if (baseUrl.startsWith("https://docs.hex-rays.com/") && !baseUrl.endsWith(".md") && !baseUrl.endsWith(".txt")) {
    candidates.unshift(baseUrl.replace(/\/+$/, "") + ".md");
  }
  for (const cand of candidates) {
    try {
      const res = await fetch(cand, {
        headers: { "User-Agent": "HexRays-OmniNexus-Edge/1.4" }
      });
      if (res.ok) {
        const txt = await res.text();
        return { url: cand, status: res.status, content: txt.slice(0, 15000) };
      }
    } catch (_) {}
  }
  return { requested: pathOrUrl, error: "Could not fetch live page; check path or use hexrays_search_docs." };
}

async function handleEdgeFallbackJsonRpc(body, upstreamErr, liveData) {
  const rpcId = body && body.id !== undefined ? body.id : 1;
  const method = (body && body.method) || "";
  const params = (body && body.params) || {};

  if (method === "initialize") {
    return {
      jsonrpc: "2.0",
      id: rpcId,
      result: {
        protocolVersion: "2025-03-26",
        capabilities: { tools: { listChanged: true } },
        serverInfo: { name: "HexRays-IDA-OmniNexus", version: "1.4.0" }
      }
    };
  }

  if (method === "notifications/initialized" || method.startsWith("notifications/")) {
    return { jsonrpc: "2.0", id: rpcId, result: {} };
  }

  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id: rpcId,
      result: { tools: EDGE_CURATED_TOOLS }
    };
  }

  if (method === "tools/call") {
    const tName = params.name || "";
    const tArgs = params.arguments || {};

    if (tName === "hexrays_list_api_and_mcp_catalog" || tName === "hexrays_search_docs") {
      const catFilter = String(tArgs.category || "").trim().toLowerCase();
      const qFilter = String(tArgs.search || tArgs.query || "").trim().toLowerCase();
      const out = {};
      for (const [k, v] of Object.entries(EDGE_CATALOG)) {
        if (catFilter && catFilter !== k) continue;
        const matched = v.items.filter((item) => !qFilter || item.toLowerCase().includes(qFilter) || v.title.toLowerCase().includes(qFilter) || k.toLowerCase().includes(qFilter));
        if (matched.length > 0) {
          out[k] = { title: v.title, base_url: v.base_url, count: matched.length, items: matched };
        }
      }
      return {
        jsonrpc: "2.0",
        id: rpcId,
        result: { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] }
      };
    }

    if (tName === "hexrays_fetch_doc_markdown") {
      const docRes = await fetchHexRaysDocAtEdge(tArgs.path_or_url || "https://docs.hex-rays.com/llms.txt");
      return {
        jsonrpc: "2.0",
        id: rpcId,
        result: { content: [{ type: "text", text: JSON.stringify(docRes, null, 2) }] }
      };
    }

    if (tName === "hexrays_doctor_and_status") {
      return {
        jsonrpc: "2.0",
        id: rpcId,
        result: {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "LIVE_EDGE_AND_CLOUD_HYBRID",
              router_version: "Hex-Rays Omni-Nexus v1.4 Zero-Cache Edge-Smart Router",
              docs_portal: "https://docs.hex-rays.com/ (IDA 9.5 + Official IDA MCP + idalib + Domain API + HCLI + IDAPython + Microcode)",
              total_categories: Object.keys(EDGE_CATALOG).length,
              backend_relay_state: liveData || { status: "ROTATING_OR_WAKING", detail: String(upstreamErr || "") }
            }, null, 2)
          }]
        }
      };
    }

    return {
      jsonrpc: "2.0",
      id: rpcId,
      result: {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: "CLOUD_RELAY_BOOTING_OR_WAKING",
            tool_requested: tName,
            message: "Your 24/7 GitHub Cloud Relay for Hex-Rays IDA Omni-Nexus is waking (~25s). Repeat this tool call shortly!",
            detail: String(upstreamErr || "")
          }, null, 2)
        }]
      }
    };
  }

  return { jsonrpc: "2.0", id: rpcId, result: {} };
}

export default {
  async fetch(request) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept, MCP-Session-Id, Last-Event-ID"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    let parsedBody = null;
    let rawBodyBuffer = undefined;
    if (request.method !== "GET" && request.method !== "HEAD") {
      rawBodyBuffer = await request.arrayBuffer();
      try {
        parsedBody = JSON.parse(new TextDecoder().decode(rawBodyBuffer));
      } catch (_) {}
    }

    if (parsedBody && (
      parsedBody.method === "initialize" ||
      parsedBody.method === "notifications/initialized" ||
      parsedBody.method === "tools/list" ||
      (parsedBody.method === "tools/call" && parsedBody.params && (
        parsedBody.params.name === "hexrays_list_api_and_mcp_catalog" ||
        parsedBody.params.name === "hexrays_search_docs" ||
        parsedBody.params.name === "hexrays_fetch_doc_markdown"
      ))
    )) {
      return new Response(JSON.stringify(await handleEdgeFallbackJsonRpc(parsedBody, null, null)), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    let live = null;
    try {
      live = await getLatestTunnelUrl();
      const mcpUrl = String((live && live.mcp_url) || "").trim();
      if (!mcpUrl.startsWith("https://")) {
        throw new Error("LIVE_MCP_URL.json mcp_url is not a full https:// URL yet: " + JSON.stringify(mcpUrl));
      }
      const targetBase = (live.gui_url && String(live.gui_url).startsWith("https://") ? live.gui_url : mcpUrl.replace(/\/mcp$/, "")).replace(/\/$/, "");
      const targetUrl = targetBase + url.pathname + url.search;

      if (request.method === "GET" && (url.pathname === "/status" || url.pathname === "/router-status")) {
        return new Response(JSON.stringify({
          router: "Hex-Rays Omni-Nexus v1.4 Zero-Cache Edge-Smart Router",
          active_backend_mcp_url: live.mcp_url,
          active_backend_gui_url: live.gui_url,
          updated_at: live.updated_at
        }, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      const proxyReq = new Request(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: rawBodyBuffer,
      });
      const resp = await fetch(proxyReq);
      if (resp.status === 530 || resp.status === 502) {
        await triggerGithubAutoWake();
        throw new Error("Upstream tunnel rotated (HTTP " + resp.status + ") - triggered Auto-Wake!");
      }
      const newHeaders = new Headers(resp.headers);
      newHeaders.set("Access-Control-Allow-Origin", "*");
      return new Response(resp.body, { status: resp.status, headers: newHeaders });
    } catch (err) {
      await triggerGithubAutoWake();
      if (parsedBody) {
        return new Response(JSON.stringify(await handleEdgeFallbackJsonRpc(parsedBody, err, live)), {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      return new Response(JSON.stringify({
        status: "AUTO_WAKING_CLOUD_RELAY",
        router: "Hex-Rays Omni-Nexus v1.4 Zero-Cache Edge-Smart Router",
        docs_portal: "https://docs.hex-rays.com/",
        live_json_state: live,
        message: "Signaled your 24/7 Hex-Rays GitHub Cloud Relay to wake (~25s).",
        error: String(err)
      }, null, 2), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
  }
};
