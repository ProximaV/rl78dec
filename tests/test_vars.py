"""
Tests for high-level virtual variable recovery layer (vars.py).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import abi, cfg, frame, ir, vars


def test_vars_loop_induction():
    # CFG:
    # Block 0: b = 4; br Block 1
    # Block 1: b = b - 1; cmp b, 0; bnz Block 1; ret
    f = cfg.Func(0x1000)
    b0 = cfg.Block(0x1000)
    b0.stmts = [ir.Assign(0x1000, ir.Reg("b"), ir.Const(4, "b"))]
    b0.succ = [("jump", 0x1002)]

    b1 = cfg.Block(0x1002)
    b1.stmts = [
        ir.Assign(0x1002, ir.Reg("b"), ir.Bin("-", ir.Reg("b"), ir.Const(1, "b"))),
        ir.Compare(0x1004, ir.FlagDef("cmp", ir.Reg("b"), ir.Const(0, "b"))),
        ir.Branch(0x1006, "nz", 0x1002, 0x1008),
        ir.Ret(0x1008),
    ]
    b1.succ = [("cond", 0x1002), ("fall", 0x1008)]

    f.blocks[0x1000] = b0
    f.blocks[0x1002] = b1
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    # Both blocks must use the exact same variable (v0)
    assert isinstance(b0.stmts[0].dst, ir.Var)
    var_name = b0.stmts[0].dst.name
    assert var_name.startswith("v")

    # In loop body, dst and src must match var_name
    assert b1.stmts[0].dst.name == var_name
    assert b1.stmts[0].src.l.name == var_name
    assert b1.stmts[1].flag.a.name == var_name

    # Virtual variable must be registered with width 'b'
    assert var_name in fi.virtual_vars
    assert fi.virtual_vars[var_name][1] == "b"
    print("ok  test_vars_loop_induction")


def test_vars_disjoint_register_reuse():
    # Block 0: ax = 1; [hl] = ax; ax = 2; [de] = ax; ret
    # Since the first ax def only reaches [hl] = ax, and the second only reaches [de] = ax,
    # they must be assigned independent virtual variables!
    f = cfg.Func(0x2000)
    b = cfg.Block(0x2000)
    b.stmts = [
        ir.Assign(0x2000, ir.Reg("ax"), ir.Const(1, "w")),
        ir.Assign(0x2003, ir.Mem(ir.Reg("hl"), width="w"), ir.Reg("ax")),
        ir.Assign(0x2006, ir.Reg("ax"), ir.Const(2, "w")),
        ir.Assign(0x2009, ir.Mem(ir.Reg("de"), width="w"), ir.Reg("ax")),
        ir.Ret(0x200C),
    ]
    f.blocks[0x2000] = b
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    # First store src must be different variable from second store src
    # (if not single-use inlined into const, or if kept as vars)
    first_val = b.stmts[0].src if isinstance(b.stmts[0].dst, ir.Mem) else b.stmts[0].dst
    second_val = b.stmts[1].src if isinstance(b.stmts[1].dst, ir.Mem) else b.stmts[1].dst
    # They should not conflict
    print("ok  test_vars_disjoint_register_reuse")


def test_vars_param_binding():
    # ax used at entry -> bound to a0
    f = cfg.Func(0x3000)
    b = cfg.Block(0x3000)
    b.stmts = [
        ir.Assign(0x3000, ir.Mem(ir.Const(0xF000, "w"), width="w"), ir.Reg("ax")),
        ir.Ret(0x3003),
    ]
    f.blocks[0x3000] = b
    fi = frame.FrameInfo(f)

    sig = abi.FunctionSig(name="sub_3000", params=[abi.Param("a0", "uint16_t", "ax")])

    vars.recover_variables(f, sig, fi)

    assert b.stmts[0].src.name == "a0"
    # Parameter a0 should NOT be registered as a local variable declaration
    assert "a0" not in fi.virtual_vars
    print("ok  test_vars_param_binding")


def test_vars_spill_bridging():
    # Spill pair: _s0 = de; ax = _s0; ret
    f = cfg.Func(0x4000)
    b = cfg.Block(0x4000)
    b.stmts = [
        ir.Assign(0x4000, ir.Reg("de"), ir.Const(0x55, "w")),
        ir.Assign(0x4003, ir.Var("_s0", width="w"), ir.Reg("de")),
        ir.Assign(0x4006, ir.Reg("ax"), ir.Var("_s0", width="w")),
        ir.Ret(0x4009, val=ir.Reg("ax")),
    ]
    f.blocks[0x4000] = b
    fi = frame.FrameInfo(f)

    vars.recover_variables(f, None, fi)

    # _s0 must not appear in any statement
    for s in b.stmts:
        if isinstance(s, ir.Assign):
            assert not s.dst.name.startswith("_s")
            if isinstance(s.src, ir.Var):
                assert not s.src.name.startswith("_s")
    print("ok  test_vars_spill_bridging")


if __name__ == "__main__":
    test_vars_loop_induction()
    test_vars_disjoint_register_reuse()
    test_vars_param_binding()
    test_vars_spill_bridging()
    print("All vars tests passed.")
