#!/usr/bin/env python3
"""
Tier 5 Headless IDA Pro 9.5 Verification & Corpus Benchmark for rl78dec.

Verifies on a %TEMP% copy of DOL-1001-VTE-1001-00703030.i64 (2,163 functions):
  1. Strict RL78 processor gating (`PH.id == 0x8078`) and zero-import `ida_hexrays` bridge.
  2. 2,163 / 2,163 functions decompile with 0 failures, 0 IR problems (`verify_ir=true`),
     and 0 `__rl78_unhandled_` markers.
  3. Full corpus C syntax & type check via real MSVC `cl.exe /Zs /W3 /TC` against
     `.agents/skills/decompiler-qa-audit/resources/rl78dec_audit_prelude.h` (NO fake
     `ax`/`bc`/`sp`/`push`/`pop` stubs — leaked hidden statements must fail!).
  4. Hex-Rays compatibility contract: `ida_hexrays.decompile(ea)`, `ctree_visitor_t`
     (including `cit_switch`), live AST mutation (`swap_branches` / `n._value`),
     `$ rl78dec` netnode persistence, and `COLOR_ADDR` line anchors.

Usage:
  python ctests/ida_verify_and_bench.py [--idat "C:\\Program Files\\IDA Professional 9.5\\idat.exe"]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


DEFAULT_IDAT = r"C:\Program Files\IDA Professional 9.5\idat.exe"


def find_vcvars64() -> Path | None:
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    vswhere = Path(pf86) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if vswhere.exists():
        res = subprocess.run(
            [str(vswhere), "-latest", "-products", "*", "-property", "installationPath"],
            capture_output=True,
            text=True,
            check=False,
        )
        inst = res.stdout.strip()
        if inst:
            cand = Path(inst) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
            if cand.exists():
                return cand
    for year in ("18", "2026", "2022"):
        for ed in ("Professional", "Enterprise", "Community", "BuildTools"):
            cand = Path(rf"C:\Program Files\Microsoft Visual Studio\{year}\{ed}\VC\Auxiliary\Build\vcvars64.bat")
            if cand.exists():
                return cand
    return None


def compile_corpus_c(c_file: Path, prelude_h: Path) -> tuple[bool, list[str]]:
    vcvars = find_vcvars64()
    if not vcvars:
        return False, ["MSVC vcvars64.bat not found"]

    src = c_file.read_text(encoding="utf-8", errors="replace")
    # Forward-declare only the functions defined in the corpus so mutually recursive calls resolve.
    # Intentionally DO NOT stub raw registers (`ax`, `bc`, `sp`) or `push`/`pop` — those are bugs!
    sigs = []
    for m in re.finditer(r"^(?:void|uint8_t|uint16_t|uint32_t|int8_t|int16_t|int32_t|bool)\s+[A-Za-z_][A-Za-z0-9_.]*\([^)]*\)$", src, re.M):
        sigs.append(m.group(0) + ";")

    with tempfile.TemporaryDirectory(prefix="rl78dec_corpus_cl_") as td:
        tu = Path(td) / "corpus_tu.c"
        tu.write_text(
            f'#include "{prelude_h.as_posix()}"\n\n' + "\n".join(sigs) + "\n\n" + src + "\n",
            encoding="utf-8",
        )
        bat = Path(td) / "run_cl.bat"
        bat.write_text(
            f'@echo off\r\ncall "{vcvars}" >nul 2>&1\r\nif errorlevel 1 exit /b 1\r\ncl.exe /nologo /Zs /W3 /TC "{tu}"\r\n',
            encoding="utf-8",
        )
        proc = subprocess.run(["cmd.exe", "/c", str(bat)], capture_output=True, text=True, check=False)
        out = (proc.stdout + "\n" + proc.stderr).strip()
        errs = [ln for ln in out.splitlines() if "error C" in ln]
        return proc.returncode == 0, errs[:50]


def verify_syscon_db(idat: Path, ws: Path, prelude_h: Path) -> tuple[dict, list[str]]:
    i64_src = ws / "syscon-1.01.bin.i64"
    if not i64_src.exists():
        return {"present": False}, [f"syscon-1.01.bin.i64 not found at {i64_src}"]

    with tempfile.TemporaryDirectory(prefix="rl78dec_syscon_verify_") as tmpdir:
        td = Path(tmpdir)
        i64_copy = td / i64_src.name
        shutil.copy2(i64_src, i64_copy)
        report_json = td / "syscon_report.json"
        corpus_c = td / "syscon_all.c"
        ida_script = td / "syscon_check.py"

        ida_script.write_text(
            f'''import json
import re
import time
import ida_auto
import ida_funcs
import ida_hexrays
import ida_idp
import ida_pro
import rl78dec

ida_auto.auto_wait()

t0 = time.perf_counter()
proc_id = ida_idp.ph_get_id()
hx_ok = bool(ida_hexrays.init_hexrays_plugin())
func_qty = ida_funcs.get_func_qty()
all_text = rl78dec.decompile_all(r"{corpus_c.as_posix()}")
elapsed = time.perf_counter() - t0

lines = all_text.splitlines()
failed_funcs = [l for l in lines if l.startswith("// Failed ")]
ir_problems = [l for l in lines if "// IR problem:" in l]
unhandled = [l for l in lines if "__rl78_unhandled_" in l]
es_mem8_cnt = len(re.findall(r"\\bes_mem8\\b", all_text))
mem8_cnt = len(re.findall(r"\\bmem8\\b", all_text))

cf_rdyq = ida_hexrays.decompile(0x6F44)
rdyq_txt = str(cf_rdyq) if cf_rdyq else ""
cf_q = ida_hexrays.decompile(0x6F8C)
q_txt = str(cf_q) if cf_q else ""

rep = {{
    "present": True,
    "proc_id": hex(proc_id),
    "hexrays_init": hx_ok,
    "func_qty": func_qty,
    "elapsed_sec": round(elapsed, 3),
    "failed_count": len(failed_funcs),
    "ir_problem_count": len(ir_problems),
    "unhandled_count": len(unhandled),
    "es_mem8_count": es_mem8_cnt,
    "mem8_count": mem8_cnt,
    "rdyq_has_syms": all(s in rdyq_txt for s in ("byte_FB3E5", "word_FB2CE", "word_FB2CA", "word_FB2C8")),
    "rdyq_no_es_mem8": ("es_mem8" not in rdyq_txt and "mem8" not in rdyq_txt),
    "q_has_two_params": bool(cf_q and len(cf_q.arguments) >= 2),
    "q_no_raw_v_zero_deref": ("*(uint8_t *)(0xF0000u | (uint16_t)(v7))" not in q_txt),
}}
with open(r"{report_json.as_posix()}", "w", encoding="utf-8") as fp:
    json.dump(rep, fp, indent=2)
ida_pro.qexit(0)
''',
            encoding="utf-8",
        )
        proc = subprocess.run(
            [str(idat), "-A", f"-S{ida_script}", str(i64_copy)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not report_json.exists():
            return {"present": True}, [f"idat.exe failed on syscon-1.01.bin.i64 rc={proc.returncode}"]

        rep = json.loads(report_json.read_text(encoding="utf-8"))
        c_ok, c_errs = compile_corpus_c(corpus_c, prelude_h)
        rep["cl_corpus_ok"] = c_ok
        rep["cl_corpus_errors"] = c_errs

        errs = []
        if rep["proc_id"] != "0x8078":
            errs.append(f"syscon: expected proc_id 0x8078, got {rep['proc_id']}")
        if not rep["hexrays_init"]:
            errs.append("syscon: init_hexrays_plugin() returned False")
        if rep["func_qty"] < 1700:
            errs.append(f"syscon: unexpected func_qty {rep['func_qty']}")
        if rep["failed_count"] != 0:
            errs.append(f"syscon: {rep['failed_count']} function(s) failed decompilation")
        if rep["ir_problem_count"] != 0:
            errs.append(f"syscon: {rep['ir_problem_count']} IR problem(s)")
        if rep["unhandled_count"] != 0:
            errs.append(f"syscon: {rep['unhandled_count']} __rl78_unhandled_ marker(s)")
        if rep["es_mem8_count"] != 0 or rep["mem8_count"] != 0:
            errs.append(f"syscon: mem8/es_mem8 leaked (es_mem8={rep['es_mem8_count']}, mem8={rep['mem8_count']})")
        if not rep["rdyq_has_syms"] or not rep["rdyq_no_es_mem8"]:
            errs.append("syscon: itron_rdyq_remove (0x6F44) missing expected symbols or leaked mem8/es_mem8")
        if not rep["q_has_two_params"] or not rep["q_no_raw_v_zero_deref"]:
            errs.append("syscon: itron_queue_remove (0x6F8C) dropped DE register parameter into uninitialized local")
        if not c_ok:
            errs.append(f"syscon: corpus C failed cl.exe /Zs /W3 /TC ({len(c_errs)} errors)")
        return rep, errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--idat", default=DEFAULT_IDAT, help="Path to IDA 9.5 idat.exe")
    ap.add_argument("--workspace", default=".", help="Path to rl78dec repository root")
    args = ap.parse_args()

    ws = Path(args.workspace).resolve()
    idat = Path(args.idat)
    i64_src = ws / "DOL-1001-VTE-1001-00703030.i64"
    prelude_h = ws / ".agents" / "skills" / "decompiler-qa-audit" / "resources" / "rl78dec_audit_prelude.h"

    if not idat.exists():
        print(f"ERROR: idat.exe not found at {idat}", file=sys.stderr)
        return 1
    if not i64_src.exists():
        print(f"ERROR: Firmware database not found at {i64_src}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="rl78dec_ida_verify_") as tmpdir:
        td = Path(tmpdir)
        i64_copy = td / i64_src.name
        shutil.copy2(i64_src, i64_copy)
        report_json = td / "ida_report.json"
        corpus_c = td / "corpus_all.c"
        ida_script = td / "ida_check.py"

        ida_script.write_text(
            f'''import json
import re
import time
import ida_auto
import ida_funcs
import ida_hexrays
import ida_idp
import ida_lines
import ida_netnode
import ida_pro
import rl78dec

ida_auto.auto_wait()

t0 = time.perf_counter()
proc_id = ida_idp.ph_get_id()
proc_name = ida_idp.get_idp_name() or ""
hx_ok = bool(ida_hexrays.init_hexrays_plugin())
func_qty = ida_funcs.get_func_qty()

all_text = rl78dec.decompile_all(r"{corpus_c.as_posix()}")
elapsed = time.perf_counter() - t0

lines = all_text.splitlines()
failed_funcs = [l for l in lines if l.startswith("// Failed ")]
ir_problems = [l for l in lines if "// IR problem:" in l]
unhandled = [l for l in lines if "__rl78_unhandled_" in l]
es_mem8_cnt = len(re.findall(r"\\bes_mem8\\b", all_text))
mem8_cnt = len(re.findall(r"\\bmem8\\b", all_text))

# Interactive Hex-Rays API + ctree_visitor_t + live AST mutation + COLOR_ADDR + $ rl78dec persistence
sample_eas = []
switch_ea = None
for i in range(func_qty):
    pfn = ida_funcs.getn_func(i)
    if pfn:
        if len(sample_eas) < 10:
            sample_eas.append(pfn.start_ea)
        if switch_ea is None:
            cf_probe = ida_hexrays.decompile(pfn.start_ea)
            if cf_probe and "switch (" in str(cf_probe):
                switch_ea = pfn.start_ea
    if len(sample_eas) >= 10 and switch_ea is not None:
        break

visitor_stats = {{"insns": 0, "exprs": 0, "switches": 0}}
class AuditVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
    def visit_insn(self, insn):
        visitor_stats["insns"] += 1
        if insn.op == ida_hexrays.cit_switch:
            visitor_stats["switches"] += 1
        return 0
    def visit_expr(self, expr):
        visitor_stats["exprs"] += 1
        return 0

ast_mutation_ok = False
color_addr_ok = False
netnode_ok = False
switch_visited = False

if sample_eas:
    fea = sample_eas[0]
    cf = ida_hexrays.decompile(fea)
    if cf:
        v = AuditVisitor()
        v.apply_to(cf.body, None)
        # Verify COLOR_ADDR (\\x01\\x28 + 16 hex chars) on sv lines
        sv_lines = cf.get_pseudocode()
        color_addr_ok = any(bool(re.match(r"^\\x01\\x28[0-9A-Fa-f]{{16}}", str(sl))) for sl in sv_lines)

        # Live AST mutation check
        mut_res = {{"done": False}}
        class MutVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)
            def visit_expr(self, expr):
                if not mut_res["done"] and expr.op == ida_hexrays.cot_num:
                    old_v = expr.n._value
                    expr.n._value = old_v ^ 0x1
                    mut_res["done"] = True
                    return 1
                return 0
        before_str = str(cf)
        mv = MutVisitor()
        mv.apply_to(cf.body, None)
        after_str = str(cf)
        ast_mutation_ok = (not mut_res["done"]) or (before_str != after_str)

    # Persistence via $ rl78dec netnode
    rl78dec.db.set_statement_cmt(fea, fea, "QA_AUDIT_CMT")
    got_cmt = rl78dec.db.get_statement_cmt(fea, fea)
    node = ida_netnode.netnode("$ rl78dec")
    netnode_ok = (got_cmt == "QA_AUDIT_CMT") and (node != ida_netnode.BADNODE)
    rl78dec.db.set_statement_cmt(fea, fea, "")

if switch_ea is not None:
    scf = ida_hexrays.decompile(switch_ea)
    if scf:
        sv = AuditVisitor()
        sv.apply_to(scf.body, None)
        switch_visited = visitor_stats["switches"] > 0

cf_conf = ida_hexrays.decompile(0xA714)
conf_txt = str(cf_conf) if cf_conf else ""
cf_init = ida_hexrays.decompile(0xA57A)
init_txt = str(cf_init) if cf_init else ""
conf_returns_ok = (
    "uint16_t process_CONF(" in conf_txt
    and all(f"return {{rc}};" in conf_txt for rc in range(8))
)
conf_no_flag_noise = ("CY =" not in conf_txt and "ZF =" not in conf_txt)
conf_lvar_count = len(cf_conf.lvars) if cf_conf else 999
init_captures_conf = ("= process_CONF(0)" in init_txt and "= process_CONF(1)" in init_txt)

report = {{
    "proc_id": hex(proc_id),
    "proc_name": proc_name,
    "hexrays_init": hx_ok,
    "func_qty": func_qty,
    "elapsed_sec": round(elapsed, 3),
    "failed_count": len(failed_funcs),
    "failed_samples": failed_funcs[:10],
    "ir_problem_count": len(ir_problems),
    "ir_problem_samples": ir_problems[:10],
    "unhandled_count": len(unhandled),
    "unhandled_samples": unhandled[:10],
    "es_mem8_count": es_mem8_cnt,
    "mem8_count": mem8_cnt,
    "visitor_stats": visitor_stats,
    "switch_ea": hex(switch_ea) if switch_ea is not None else None,
    "switch_visited": switch_visited,
    "ast_mutation_ok": ast_mutation_ok,
    "color_addr_ok": color_addr_ok,
    "netnode_ok": netnode_ok,
    "process_conf_returns_ok": conf_returns_ok,
    "process_conf_no_flag_noise": conf_no_flag_noise,
    "process_conf_lvar_count": conf_lvar_count,
    "init_configs_captures_conf": init_captures_conf,
}}
with open(r"{report_json.as_posix()}", "w", encoding="utf-8") as fp:
    json.dump(report, fp, indent=2)
ida_pro.qexit(0)
''',
            encoding="utf-8",
        )

        proc = subprocess.run(
            [str(idat), "-A", f"-S{ida_script}", str(i64_copy)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not report_json.exists():
            print(f"ERROR: idat.exe failed rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}", file=sys.stderr)
            return 1

        report = json.loads(report_json.read_text(encoding="utf-8"))
        c_ok, c_errs = compile_corpus_c(corpus_c, prelude_h)
        report["cl_corpus_ok"] = c_ok
        report["cl_corpus_errors"] = c_errs

        print(json.dumps(report, indent=2))

        failures = []
        if report["proc_id"] != "0x8078":
            failures.append(f"Expected proc_id 0x8078, got {report['proc_id']}")
        if not report["hexrays_init"]:
            failures.append("ida_hexrays.init_hexrays_plugin() returned False")
        if report["func_qty"] != 2163:
            failures.append(f"Expected 2163 functions, got {report['func_qty']}")
        if report["failed_count"] != 0:
            failures.append(f"{report['failed_count']} function(s) failed decompilation")
        if report["ir_problem_count"] != 0:
            failures.append(f"{report['ir_problem_count']} IR verification problem(s) detected (verify_ir=true)")
        if report["unhandled_count"] != 0:
            failures.append(f"{report['unhandled_count']} __rl78_unhandled_ marker(s) detected")
        if report.get("es_mem8_count", 0) != 0:
            failures.append(f"{report['es_mem8_count']} es_mem8 intrinsic reference(s) detected")
        if report.get("mem8_count", 0) != 0:
            failures.append(f"{report['mem8_count']} mem8 intrinsic reference(s) detected")
        if not report["color_addr_ok"]:
            failures.append("Missing COLOR_ADDR tags on pseudocode lines")
        if not report["netnode_ok"]:
            failures.append("$ rl78dec netnode persistence failed")
        if not report["ast_mutation_ok"]:
            failures.append("Live ctree AST mutation failed to update printed text")
        if report["switch_ea"] is not None and not report["switch_visited"]:
            failures.append("ctree_visitor_t failed to visit cit_switch node (cit_switch missing from JSON/visitor)")
        if not report.get("process_conf_returns_ok", False):
            failures.append("process_CONF (0xA714) missing uint16_t return or shared-epilogue BC return codes 0..7")
        if not report.get("process_conf_no_flag_noise", False):
            failures.append("process_CONF (0xA714) leaked redundant CY = / ZF = statements")
        if report.get("process_conf_lvar_count", 999) > 18:
            failures.append(f"process_CONF (0xA714) has excessive temporaries ({report.get('process_conf_lvar_count')})")
        if not report.get("init_configs_captures_conf", False):
            failures.append("init_configs (0xA57A) failed to capture process_CONF return values")
        if not c_ok:
            failures.append(f"Corpus C output failed cl.exe /Zs /W3 /TC ({len(c_errs)} sample errors)")

        syscon_rep, syscon_errs = verify_syscon_db(idat, ws, prelude_h)
        print(json.dumps({"syscon": syscon_rep}, indent=2))
        failures.extend(syscon_errs)

        if failures:
            print("\n=== TIER 5 CORPUS GATE: FAIL ===")
            for f in failures:
                print(" -", f)
            return 2

        print("\n=== TIER 5 CORPUS GATE: PASS ===")
        return 0


if __name__ == "__main__":
    sys.exit(main())
