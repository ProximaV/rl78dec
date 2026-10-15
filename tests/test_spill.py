"""
Tests for abstract stack simulation and spill/reload elimination.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import cfg, frame, ir, spill


def test_spill_call_argument_recovery():
    # Simulate: push ax; push bc; call sub_1000; addw sp, #4
    f = cfg.Func(0x2000)
    b = cfg.Block(0x2000)
    push_ax = ir.Intrinsic(0x2000, "push", [ir.Reg("ax")])
    push_bc = ir.Intrinsic(0x2002, "push", [ir.Reg("bc")])
    call_stmt = ir.Call(0x2004, target=0x1000)
    cleanup = ir.Assign(0x2007, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(4, "b")))
    ret_stmt = ir.Ret(0x2009)

    b.stmts = [push_ax, push_bc, call_stmt, cleanup, ret_stmt]
    f.blocks[0x2000] = b
    fi = frame.FrameInfo(f)

    spill.eliminate_spills(f, fi)

    # Pusher intrinsics and SP cleanup must be hidden
    assert id(push_ax) in fi.hidden_stmts
    assert id(push_bc) in fi.hidden_stmts
    assert id(cleanup) in fi.hidden_stmts

    # Call statement must have received the stack arguments in left-to-right order (pushed right-to-left)
    assert len(call_stmt.args) == 2
    assert call_stmt.args[0] == ir.Reg("bc")
    assert call_stmt.args[1] == ir.Reg("ax")
    print("ok  test_spill_call_argument_recovery")


def test_spill_push_pop_elimination():
    # Simulate: push de; movw de, #0x1234; pop ax; ret
    f = cfg.Func(0x3000)
    b = cfg.Block(0x3000)
    push_de = ir.Intrinsic(0x3000, "push", [ir.Reg("de")])
    inner_calc = ir.Assign(0x3002, ir.Reg("de"), ir.Const(0x1234, "w"))
    pop_ax = ir.Intrinsic(0x3005, "pop", [ir.Reg("ax")])
    ret_stmt = ir.Ret(0x3007)

    b.stmts = [push_de, inner_calc, pop_ax, ret_stmt]
    f.blocks[0x3000] = b
    fi = frame.FrameInfo(f)

    spill.eliminate_spills(f, fi)

    # push and pop must be replaced with spill variable assignments
    op_names = [s.name if isinstance(s, ir.Intrinsic) else None for s in b.stmts]
    assert "push" not in op_names
    assert "pop" not in op_names

    # There should now be an assignment to a spill variable and a restore from it
    spill_def = b.stmts[0]
    spill_use = b.stmts[2]
    assert isinstance(spill_def, ir.Assign) and spill_def.dst.name.startswith("_s")
    assert isinstance(spill_use, ir.Assign) and spill_use.src.name.startswith("_s")
    print("ok  test_spill_push_pop_elimination")


if __name__ == "__main__":
    test_spill_call_argument_recovery()
    test_spill_push_pop_elimination()
    print("All spill tests passed.")
