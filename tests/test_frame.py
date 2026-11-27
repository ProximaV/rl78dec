"""
Tests for stack frame analysis, local variable recovery, and prologue/epilogue suppression.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import cfg, decompile_image, frame, ir


def test_frame_analysis_ir():
    func = cfg.Func(0x1000)
    func.name = "test_func"
    b0 = cfg.Block(0x1000)

    # Prologue: push hl, subw sp, 4, movw hl, sp
    p_push = ir.Intrinsic(0x1000, "push", [ir.Reg("hl")])
    p_sub = ir.Assign(0x1001, ir.Reg("sp"), ir.Bin("-", ir.Reg("sp"), ir.Const(4)))
    p_mov = ir.Assign(0x1003, ir.Reg("hl"), ir.Reg("sp"))

    # Body accessing local var at disp 2 ([hl+2]) and stack arg at disp 10 ([hl+10])
    # disp < frsize (4): 4 - 2 = 2 -> var_2
    # disp >= arg_base (4 + 2 + 4 = 10): 10 - 10 = 0 -> arg_0
    s_local = ir.Assign(0x1005, ir.Mem(ir.Bin("+", ir.Reg("hl"), ir.Const(2)), "w"), ir.Const(0x1234))
    s_arg = ir.Assign(0x1007, ir.Reg("ax"), ir.Mem(ir.Bin("+", ir.Reg("hl"), ir.Const(10)), "w"))

    # Epilogue: addw sp, 4, pop hl, ret
    e_add = ir.Assign(0x1009, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(4)))
    e_pop = ir.Intrinsic(0x100B, "pop", [ir.Reg("hl")])
    e_ret = ir.Ret(0x100C)

    b0.stmts = [p_push, p_sub, p_mov, s_local, s_arg, e_add, e_pop, e_ret]
    func.blocks[0x1000] = b0

    info = frame.analyze_frame(func)

    assert info.has_frame
    assert info.fp_reg == "hl"
    assert info.frame_size == 4
    assert info.saved_regs == ["hl"]
    assert "var_2" in info.locals
    assert "arg_0" in info.args

    # Check transformed IR expressions
    assert isinstance(s_local.dst, ir.StackVar) and s_local.dst.name == "var_2"
    assert not s_local.dst.is_arg
    assert isinstance(s_arg.src, ir.StackVar) and s_arg.src.name == "arg_0"
    assert s_arg.src.is_arg

    # Check boilerplate hidden
    assert id(p_push) in info.hidden_stmts
    assert id(p_sub) in info.hidden_stmts
    assert id(p_mov) in info.hidden_stmts
    assert id(e_add) in info.hidden_stmts
    assert id(e_pop) in info.hidden_stmts
    assert id(s_local) not in info.hidden_stmts
    assert id(s_arg) not in info.hidden_stmts

    print("ok  test_frame_analysis_ir")


def test_frame_sp_direct():
    func = cfg.Func(0x2000)
    func.name = "sp_func"
    b0 = cfg.Block(0x2000)

    p_sub = ir.Assign(0x2000, ir.Reg("sp"), ir.Bin("-", ir.Reg("sp"), ir.Const(6)))
    s_local = ir.Assign(0x2002, ir.Mem(ir.Bin("+", ir.Reg("sp"), ir.Const(2)), "w"), ir.Const(0x42))
    e_add = ir.Assign(0x2004, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(6)))
    e_ret = ir.Ret(0x2006)

    b0.stmts = [p_sub, s_local, e_add, e_ret]
    func.blocks[0x2000] = b0

    info = frame.analyze_frame(func)

    assert info.has_frame
    assert info.fp_reg == "sp"
    assert info.frame_size == 6
    assert info.saved_regs == []
    # frsize = 6, disp = 2 -> 6 - 2 = 4 -> var_4
    assert "var_4" in info.locals
    assert isinstance(s_local.dst, ir.StackVar) and s_local.dst.name == "var_4"

    print("ok  test_frame_sp_direct")


def test_frame_end_to_end_decompilation():
    # Construct binary sequence:
    # 0xC7:          push hl
    # 0x20, 0x04:    subw sp, #4
    # 0xFB, 0xF8, 0xFF: movw hl, !0xFFF8 (SP)
    # 0xBC, 0x02:    movw [hl+2], ax
    # 0x10, 0x04:    addw sp, #4
    # 0xC6:          pop hl
    # 0xD7:          ret
    raw = bytes([
        0xC7,
        0x20, 0x04,
        0xFB, 0xF8, 0xFF,
        0xBC, 0x02,
        0x10, 0x04,
        0xC6,
        0xD7
    ])
    buf = bytearray(0x100)
    buf[:len(raw)] = raw

    prog = decompile_image(buf, entries=[0])
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)

    # Verify frame declarations and boilerplate suppression
    assert "uint16_t var_2;" in text, text
    assert "push(" not in text, text
    assert "pop(" not in text, text
    assert "sp = sp" not in text, text
    assert "hl = sp" not in text, text
    assert "var_2 = a0;" in text, text
    assert "return;" in text, text

    print("ok  test_frame_end_to_end_decompilation")


if __name__ == "__main__":
    test_frame_analysis_ir()
    test_frame_sp_direct()
    test_frame_end_to_end_decompilation()
    print("\nall frame tests passed")
