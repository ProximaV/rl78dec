"""
Headless tests for the RL78 decoder and decompiler pipeline.  No IDA, no ROM.

    python tests/test_pipeline.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import decoder, decompile_image        # noqa: E402


def _img(b, size=0x100):
    a = bytearray(size)
    a[:len(b)] = bytes(b)
    return a


def test_decode_fields():
    # mov x, #0x12   (0x50 = mov X,#byte)
    ins = decoder.decode_one(_img([0x50, 0x12]), 0)
    assert ins.mnem == "mov" and ins.size == 2
    assert ins.ops[0].mode == "reg" and ins.ops[0].reg == "x"
    assert ins.ops[1].mode == "imm" and ins.ops[1].value == 0x12

    # mov a, [hl]   (0x8B)
    ins = decoder.decode_one(_img([0x8B]), 0)
    assert ins.mnem == "mov" and ins.ops[1].mode == "ind" and ins.ops[1].base_reg == "hl"

    # br !!0x0F1234  (0xEC, addr20)
    ins = decoder.decode_one(_img([0xEC, 0x34, 0x12, 0x0F]), 0)
    assert ins.mnem == "br" and ins.ops[0].mode == "far" and ins.ops[0].addr == 0x0F1234

    # bz $rel  at ea=0x10, disp=+2 -> target = 0x10 + 2 + 2 = 0x14
    ins = decoder.decode_one(_img([0] * 0x10 + [0xDD, 0x02]), 0x10)
    assert ins.mnem == "bz" and ins.ops[0].addr == 0x14

    # ES: mov a, !addr16  (0x11 prefix) -> es data at raw addr16 (no 0xF0000)
    ins = decoder.decode_one(_img([0x11, 0x8F, 0x00, 0x10]), 0)
    assert ins.es and ins.mnem == "mov"
    assert ins.ops[1].mode == "mem" and ins.ops[1].es and ins.ops[1].addr == 0x1000

    # 0x71 map: set1 cy = 71 80 ; clr1 cy = 71 88
    ins = decoder.decode_one(_img([0x71, 0x80]), 0)
    assert ins.mnem == "set1" and ins.ops[0].reg == "cy"
    ins = decoder.decode_one(_img([0x71, 0x88]), 0)
    assert ins.mnem == "clr1" and ins.ops[0].reg == "cy"

    # 0x61 map: xch a, b = 61 8B
    ins = decoder.decode_one(_img([0x61, 0x8B]), 0)
    assert ins.mnem == "xch" and ins.ops[0].reg == "a" and ins.ops[1].reg == "b"

    print("ok  test_decode_fields")


def test_all_first_bytes():
    # every first byte must decode or cleanly return None, never raise
    for b in range(256):
        decoder.decode_one(_img([b, 0, 0, 0, 0]), 0)
        decoder.decode_one(_img([0x11, b, 0, 0, 0]), 0)   # with ES prefix
        for pfx in (0x31, 0x61, 0x71):
            decoder.decode_one(_img([pfx, b, 0, 0]), 0)
    print("ok  test_all_first_bytes")


def test_loop_structuring():
    # mov b,#4 ; L: dec b ; bnz L ; ret
    #   0x53 0x04 | 0x93 | 0xDF <disp> | 0xD7
    # bnz at ea=3, target L=2 -> disp = 2 - (3+2) = -3 = 0xFD
    prog = decompile_image(_img([0x53, 0x04, 0x93, 0xDF, 0xFD, 0xD7]), entries=[0])
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert "do {" in text and "while (" in text and "!= 0" in text, text
    assert "v0 = v0 - 1;" in text, text
    assert text.count("{") == text.count("}"), text
    print("ok  test_loop_structuring\n")
    print(text)


def test_switch_structuring():
    raw = bytes.fromhex(
        "5c1f9170f1312d0468d3144100118a029efc11aa00410f61cb00a4d30000a4d30000"
        "4ed40000a6d300000000000000000000b8d300000000000000000000000000000000"
        "00000000000000000000cad3000000000000d70031171169c6ddf1041fde1451ff11"
        "9a00d700c331171169c6ddf1312d0425de14c2ee5a00c331171169c6ddf1312d042d"
        "de14c2ee4800f61129efdd08045cdd14c3fe3a00c2c3d1df211129efdd7553012c08"
        "de02f3655201d1dd05311791dffb110958dd617a111858dd118f54ddc2614adf0a11"
        "8f53dd5cf7119f53ddd7112907de614add1c701189614adf0360119911290dde618a"
        "08112807de618a11280dded711ca00fff1d7c331171169c6ddf10413de14c2eec6ff"
        "1138"
    )
    buf = bytearray(0x10000)
    buf[0xD34E:0xD34E + len(raw)] = raw
    prog = decompile_image(buf, entries=[0xD34E])
    fn = prog.funcs[0xD34E]
    text = "\n".join(fn.lines)
    assert "switch (" in text, text
    assert "case 0:" in text and "case 1:" in text, text
    assert "case 2:" in text and "case 3:" in text, text
    assert "case 6:" in text and "case 13:" in text, text
    assert "break;" in text, text
    assert "return;" in text, text
    print("ok  test_switch_structuring\n")
    print(text)


def test_coalesce_arithmetic():
    # Consecutive incw ax (0xA1, 0xA1, 0xD7) -> + 2
    prog = decompile_image(_img([0xA1, 0xA1, 0xD7]), entries=[0])
    text = "\n".join(prog.funcs[0].lines)
    assert "+ 2" in text, text

    # Consecutive decw bc (0xB3, 0xB3, 0xD7) -> - 2
    prog = decompile_image(_img([0xB3, 0xB3, 0xD7]), entries=[0])
    text = "\n".join(prog.funcs[0].lines)
    assert "- 2" in text, text

    print("ok  test_coalesce_arithmetic")


def test_global_memory_access():
    # Loop copying 4 bytes using 16-bit word moves with C index:
    #   MOV C, #4
    # loop:
    #   DEC C
    #   DEC C
    #   MOVW AX, [C+0xFE48]
    #   MOVW [C+0xFE4C], AX
    #   BNZ loop
    #   MOV A, !0xFFE50
    #   RET
    raw = bytes([0x52, 0x04, 0x92, 0x92, 0x69, 0x48, 0xFE, 0x68, 0x4C, 0xFE, 0xDF, 0xF6, 0x8F, 0x50, 0xFE, 0xD7])
    buf = bytearray(0x100)
    buf[:len(raw)] = raw
    prog = decompile_image(buf, entries=[0], cell_names={
        0xFFE4C: "byte_FFE4C",
        0xFFE48: "byte_FFE48",
        0xFFE50: "byte_FFE50",
    })
    text = "\n".join(prog.funcs[0].lines)
    assert "byte_FFE4C[v0] = byte_FFE48[v0];" in text, text
    assert "return byte_FFE50;" in text or "byte_FFE50" in text, text
    assert "mem16[" not in text, text

    print("ok  test_global_memory_access")


def test_named_variable_constant():
    # ADDW AX, #0x2A0E (0x04 0x0E 0x2A) ; RET (0xD7)
    raw = bytes([0x04, 0x0E, 0x2A, 0xD7])
    buf = bytearray(0x100)
    buf[:len(raw)] = raw

    # 1. Test via cell_names mapping
    prog = decompile_image(buf, entries=[0], cell_names={0x2A0E: "kermit_cmd_tableR"})
    text = "\n".join(prog.funcs[0].lines)
    assert "kermit_cmd_tableR" in text, text
    assert "0x2A0E" not in text, text
    assert hasattr(prog.funcs[0], "line_eas")
    assert prog.funcs[0].line_eas is not None

    # 2. Test via direct instruction operand name annotation
    insns, calls = decoder.decode(buf, entries=[0], base=0)
    assert 0 in insns and len(insns[0].ops) >= 2
    insns[0].ops[1].name = "kermit_cmd_tableR"
    from rl78dec import cfg, opt, structure, cgen, frame, abi, vars
    from rl78dec.names import Namer
    f = cfg.build_func(insns, 0, {0})
    frame_info = frame.analyze_frame(f)
    opt.optimize(f)
    sig = abi.analyze_calling_convention(f, frame_info)
    vars.recover_variables(f, sig, frame_info)
    tree = structure.structure(f)
    lines = cgen.generate(f, tree, Namer(), frame_info=frame_info, sig=sig)
    text2 = "\n".join(lines)
    assert "kermit_cmd_tableR" in text2, text2
    assert "0x2A0E" not in text2, text2

    print("ok  test_named_variable_constant")


def test_struct_pointer_cascading():
    from rl78dec import decoder, cfg, opt, structure, cgen, frame, abi, vars
    from rl78dec.names import Namer

    # Byte sequence:
    # 00: ADDW AX, #0x2A0E  (kermit_cmd_tableR)
    # 03: MOVW DE, AX       (DE = AX)
    # 04: MOV ES, #0
    # 06: MOVW AX, ES:[DE]  (offset 0 -> id)
    # 08: MOV A, ES:[DE+2]  (offset 2 -> auth)
    # 0B: MOV A, ES:[DE+6]  (offset 6 -> func)
    # 0E: MOVW AX, ES:[DE+4](offset 4 -> func)
    # 11: RET
    buf = bytes([
        0x04, 0x0E, 0x2A,
        0x14,
        0x41, 0x00,
        0x11, 0xA9,
        0x11, 0x8A, 0x02,
        0x11, 0x8A, 0x06,
        0x11, 0xAA, 0x04,
        0xD7
    ])

    namer = Namer(
        struct_defs={
            'kermit_cmd0': {
                'size': 8,
                'members': [
                    {'offset': 0, 'size': 2, 'name': 'id', 'type': 'int'},
                    {'offset': 2, 'size': 2, 'name': 'auth', 'type': 'int'},
                    {'offset': 4, 'size': 4, 'name': 'func', 'type': 'void (*)()'},
                ]
            }
        },
        symbol_structs={'kermit_cmd_tableR': 'kermit_cmd0', 0x2A0E: 'kermit_cmd0'}
    )

    insns, calls = decoder.decode(buf, entries=[0], base=0)
    insns[0].ops[1].name = 'kermit_cmd_tableR'
    f = cfg.build_func(insns, 0, {0})
    frame_info = frame.analyze_frame(f)
    opt.optimize(f)
    sig = abi.analyze_calling_convention(f, frame_info)
    vars.recover_variables(f, sig, frame_info)
    tree = structure.structure(f)
    lines = cgen.generate(f, tree, namer, frame_info=frame_info, sig=sig)
    text = '\n'.join(lines)

    assert "kermit_cmd0 *v1;" in text, text
    assert "v1->id" in text, text
    assert "v1->auth" in text, text
    assert "v1->func" in text, text
    assert "es_mem" not in text, text

    print("ok  test_struct_pointer_cascading")


def test_math_simplification():
    from rl78dec import ir, opt, cgen
    from rl78dec.names import Namer

    v12 = ir.Var("v12")
    tbl = ir.Const(0x30BE, name="cp_cmd_table")

    # ((v12 + v12) + v12) + cp_cmd_table -> v12 * 3 + cp_cmd_table
    e1 = ir.Bin("+", ir.Bin("+", ir.Bin("+", v12, v12), v12), tbl)
    sim1 = opt.simplify_math(e1)
    em = cgen._Emit(Namer())
    out1 = em.expr(sim1)
    assert out1 == "v12 * 3 + cp_cmd_table", out1

    # (v6 + v6) + v6 -> v6 * 3
    v6 = ir.Var("v6")
    e2 = ir.Bin("+", ir.Bin("+", v6, v6), v6)
    sim2 = opt.simplify_math(e2)
    assert em.expr(sim2) == "v6 * 3", em.expr(sim2)

    # x + x -> x * 2
    x = ir.Var("x")
    e3 = ir.Bin("+", x, x)
    assert em.expr(opt.simplify_math(e3)) == "x * 2"

    # (x * 2) + (x * 3) -> x * 5
    e4 = ir.Bin("+", ir.Bin("*", x, ir.Const(2)), ir.Bin("*", x, ir.Const(3)))
    assert em.expr(opt.simplify_math(e4)) == "x * 5"

    # (x + 5) + 3 -> x + 8
    e5 = ir.Bin("+", ir.Bin("+", x, ir.Const(5)), ir.Const(3))
    assert em.expr(opt.simplify_math(e5)) == "x + 8"

    # (x + 5) - 5 -> x
    e6 = ir.Bin("-", ir.Bin("+", x, ir.Const(5)), ir.Const(5))
    assert em.expr(opt.simplify_math(e6)) == "x"

    # x - x -> 0
    e7 = ir.Bin("-", x, x)
    assert em.expr(opt.simplify_math(e7)) == "0"

    print("ok  test_math_simplification")


def test_brk_and_callt_semantics():
    buf = bytearray(0x300)
    # 0x007E: BRK vector -> 0x0220
    buf[0x7E] = 0x20
    buf[0x7F] = 0x02
    # 0x0080: CALLT[0x80] entry -> 0x0200
    buf[0x80] = 0x00
    buf[0x81] = 0x02

    # 0x0100: onew ax (E6) ; callt [0x0080] (61 84) ; ret (D7)
    buf[0x100:0x104] = bytes([0xE6, 0x61, 0x84, 0xD7])
    # 0x0200 (CALLT target): incw ax (A1) ; ret (D7)
    buf[0x200:0x202] = bytes([0xA1, 0xD7])

    # 0x0120: mov a, #5 (51 05) ; brk (61 CC) ; onew bc (E7) ; ret (D7)
    buf[0x120:0x126] = bytes([0x51, 0x05, 0x61, 0xCC, 0xE7, 0xD7])
    # 0x0220 (BRK handler): push ax (C1) ; mov a, #1 (51 01) ; pop ax (C0) ; retb (61 EC)
    buf[0x220:0x226] = bytes([0xC1, 0x51, 0x01, 0xC0, 0x61, 0xEC])

    # 0x0140: mov a, #1 (51 01) ; brk1 (FF) ; mov a, #2 (51 02) ; ret (D7)
    buf[0x140:0x146] = bytes([0x51, 0x01, 0xFF, 0x51, 0x02, 0xD7])

    # 0x0160: callt [0x0082] (61 94, unpopulated slot -> fallback indirect) ; ret (D7)
    buf[0x160:0x163] = bytes([0x61, 0x94, 0xD7])

    insns, calls = decoder.decode(buf, entries=[0x100, 0x120, 0x140, 0x160], base=0)

    # 1. CALLT resolves vector table [0x80] -> 0x200 and discovers callee
    assert insns[0x101].mnem == "callt"
    assert insns[0x101].ops[0].addr == 0x80
    assert insns[0x101].ops[0].value == 0x200
    assert decoder.target_of(insns[0x101]) == 0x200
    assert 0x200 in calls and 0x200 in insns

    # 2. BRK resolves vector [0x7E] -> 0x220 AND falls through to 0x124 (PC + 2)
    assert insns[0x122].mnem == "brk"
    assert decoder.target_of(insns[0x122]) == 0x220
    assert 0x220 in calls and 0x220 in insns
    assert 0x124 in insns and insns[0x124].mnem == "onew"

    # 3. BRK1 (0xFF) stops decoding and does NOT fall through to 0x143
    assert insns[0x142].mnem == "brk1"
    assert 0x143 not in insns

    # 4. End-to-end decompilation checks
    prog = decompile_image(buf, entries=[0x100, 0x120, 0x160], code_names={0x200: "ct_helper", 0x220: "swi_handler"})

    t_callt = "\n".join(prog.funcs[0x100].lines)
    assert "ct_helper(1);" in t_callt, t_callt
    assert "m_00080" not in t_callt, t_callt
    assert 0x200 in prog.funcs[0x100].cfg.calls

    t_brk = "\n".join(prog.funcs[0x120].lines)
    assert "brk();   /* swi -> swi_handler */" in t_brk, t_brk
    assert "return 1;" in t_brk, t_brk
    assert 0x220 in prog.funcs[0x120].cfg.calls

    t_swi = "\n".join(prog.funcs[0x220].lines)
    assert "void swi_handler(void)" in t_swi, t_swi
    assert "return;   /* retb */" in t_swi, t_swi

    t_unres = "\n".join(prog.funcs[0x160].lines)
    assert "(*m_00082)();" in t_unres, t_unres

    print("ok  test_brk_and_callt_semantics")


def test_es_20bit_resolution_and_formatting():
    from rl78dec import ir, opt, cgen, cfg, frame, spill, abi, vars as rvars, structure
    from rl78dec.names import Namer

    # 1. set_bit (mov1 es:[hl].1, cy) must NOT clobber ES or HL -> resolves to symbol name
    #    41 0F          mov es, #0Fh
    #    36 1E EA       movw hl, #0EA1Eh
    #    11 71 11       mov1 es:[hl].1, cy
    #    11 8B          mov a, es:[hl]
    #    D7             ret
    raw1 = bytes([0x41, 0x0F, 0x36, 0x1E, 0xEA, 0x11, 0x71, 0x11, 0x11, 0x8B, 0xD7])
    prog1 = decompile_image(_img(raw1), entries=[0], cell_names={0xFEA1E: "isVoltageDeviceThere"})
    t1 = "\n".join(prog1.funcs[0].lines)
    assert "isVoltageDeviceThere" in t1, t1
    assert "es_mem" not in t1, t1
    assert "(uint32_t)es" not in t1, t1

    # 2. Constant ES=0xF through tmp_seg (0xFFED4) + dynamic pointer offset -> *(uint8_t *)(0xF0000 | ...)
    #    51 0F          mov a, #0Fh
    #    9D D4          mov 0xFFED4, a
    #    8D D4          mov a, 0xFFED4
    #    9E FD          mov es, a
    #    14             movw de, ax     (actually let's use AX live-in as offset via movw hl, ax = 16)
    #    wait: use movw hl, bc (movw ax, bc = 13; movw hl, ax = 16) so offset is a1!
    #    13             movw ax, bc
    #    16             movw hl, ax
    #    51 0F          mov a, #0Fh
    #    9D D4          mov 0xFFED4, a
    #    8D D4          mov a, 0xFFED4
    #    9E FD          mov es, a
    #    11 8B          mov a, es:[hl]
    #    D7             ret
    raw2 = bytes([0x13, 0x16, 0x51, 0x0F, 0x9D, 0xD4, 0x8D, 0xD4, 0x9E, 0xFD, 0x11, 0x8B, 0xD7])
    prog2 = decompile_image(_img(raw2), entries=[0])
    t2 = "\n".join(prog2.funcs[0].lines)
    assert "*(uint8_t *)(0xF0000 |" in t2, t2
    assert "es_mem" not in t2, t2

    # 3. Constant ES=0xF + small struct/field offset [de + 3] must NOT become ram_0003[de]
    #    14             movw de, ax
    #    41 0F          mov es, #0Fh
    #    11 8A 03       mov a, es:[de+3]
    #    D7             ret
    raw3 = bytes([0x14, 0x41, 0x0F, 0x11, 0x8A, 0x03, 0xD7])
    prog3 = decompile_image(_img(raw3), entries=[0])
    t3 = "\n".join(prog3.funcs[0].lines)
    assert "*(uint8_t *)(0xF0000 | (a0 + 3))" in t3, t3
    assert "ram_0003" not in t3, t3
    assert "es_mem" not in t3, t3

    # 4. Constant ES=0x0 + ROM address 0x9000 must stay in segment 0 across 2-pass opt (NOT 0xF9000!)
    #    41 00          mov es, #0
    #    11 8F 00 90    mov a, es:!0x9000
    #    D7             ret
    raw4 = bytes([0x41, 0x00, 0x11, 0x8F, 0x00, 0x90, 0xD7])
    prog4 = decompile_image(_img(raw4), entries=[0], cell_names={0x09000: "rom_const_9000"})
    t4 = "\n".join(prog4.funcs[0].lines)
    assert "rom_const_9000" in t4, t4
    assert "ram_9000" not in t4, t4
    assert "es_mem" not in t4, t4

    # 5. Dynamic ES loaded from RAM variable (byte_FEC9C) -> ((uint32_t)byte_FEC9C << 16) | ...
    #    16             movw hl, ax
    #    8F 9C EC       mov a, !0xEC9C
    #    9E FD          mov es, a
    #    11 8B          mov a, es:[hl]
    #    D7             ret
    raw5 = bytes([0x16, 0x8F, 0x9C, 0xEC, 0x9E, 0xFD, 0x11, 0x8B, 0xD7])
    prog5 = decompile_image(_img(raw5), entries=[0], cell_names={0xFEC9C: "byte_FEC9C"})
    t5 = "\n".join(prog5.funcs[0].lines)
    assert "*(uint8_t *)(((uint32_t)byte_FEC9C << 16) | a0)" in t5, t5
    assert "es_mem" not in t5, t5

    # 6. Unknown live-in ES -> ((uint32_t)es << 16) | ... (no es_mem)
    #    16             movw hl, ax
    #    11 8B          mov a, es:[hl]
    #    D7             ret
    raw6 = bytes([0x16, 0x11, 0x8B, 0xD7])
    prog6 = decompile_image(_img(raw6), entries=[0])
    t6 = "\n".join(prog6.funcs[0].lines)
    assert "*(uint8_t *)(((uint32_t)es << 16) | a0)" in t6, t6
    assert "es_mem" not in t6, t6

    # 7. Split 32-bit far pointer (sub_79CC pattern: de clobbered after saving e to saddr_D5)
    b0 = cfg.Block(0x100)
    b0.stmts = [
        ir.Call(0x100, target=0x1000, dst=ir.Reg("de:bc", "d")),
        ir.Assign(0x104, ir.Reg("a", "b"), ir.Reg("e", "b")),
        ir.Assign(0x105, ir.Mem(0xFFED5, "b"), ir.Reg("a", "b")),
        ir.Assign(0x107, ir.Reg("es", "b"), ir.Mem(0xFFED5, "b")),
        ir.Assign(0x10A, ir.Reg("de", "w"), ir.Const(0x1234, "w")),
        ir.Assign(0x10D, ir.Reg("a", "b"), ir.Mem(ir.Bin("+", ir.Reg("bc", "w"), ir.Const(0xCA, "a")), "b", es=True)),
        ir.Ret(0x111, val=ir.Reg("a", "b")),
    ]
    b0.term = "ret"
    f7 = cfg.Func(0x100)
    f7.blocks[0x100] = b0
    f7.name = "sub_split_far"
    fi7 = frame.FrameInfo(f7)
    opt.optimize(f7)
    sig7 = abi.FunctionSig(name="sub_split_far", ret_type="uint8_t", ret_expr=ir.Reg("a", "b"), params=[])
    rvars.recover_variables(f7, sig7, fi7)
    tree7 = structure.structure(f7)
    t7 = "\n".join(cgen.generate(f7, tree7, Namer(), frame_info=fi7, sig=sig7))
    assert "*(uint8_t *)(v0 + 0xCA)" in t7, t7
    assert "es_mem" not in t7, t7
    assert "(uint32_t)es" not in t7, t7

    # 8. Spilled es:[de+2] call argument inherits resolved ES from its push site (sub_6AAA pattern)
    b8 = cfg.Block(0x200)
    b8.stmts = [
        ir.Assign(0x200, ir.Reg("es", "b"), ir.Const(0, "b")),
        ir.Assign(0x202, ir.Reg("ax", "w"), ir.Mem(ir.Bin("+", ir.Reg("de", "w"), ir.Const(2, "b")), "w", es=True)),
        ir.Intrinsic(0x204, "push", [ir.Reg("ax", "w")]),
        ir.Assign(0x205, ir.Reg("ax", "w"), ir.Const(0x9999, "w")),
        ir.Call(0x208, target=0x300),
        ir.Assign(0x20C, ir.Reg("sp", "w"), ir.Bin("+", ir.Reg("sp", "w"), ir.Const(2, "w"))),
        ir.Ret(0x20E),
    ]
    b8.term = "ret"
    f8 = cfg.Func(0x200)
    f8.blocks[0x200] = b8
    f8.name = "sub_spill_es"
    fi8 = frame.FrameInfo(f8)
    spill.eliminate_spills(f8, fi8)
    opt.optimize(f8)
    sig8 = abi.FunctionSig(name="sub_spill_es", ret_type="void", ret_expr=None, params=[])
    rvars.recover_variables(f8, sig8, fi8)
    tree8 = structure.structure(f8)
    t8 = "\n".join(cgen.generate(f8, tree8, Namer(), frame_info=fi8, sig=sig8))
    assert "*(uint16_t *)(" in t8 and "+ 2)" in t8, t8
    assert "(uint32_t)es" not in t8, t8
    assert "es_mem" not in t8, t8

    # 9. cgen guards: simplify_math collapsing Bin -> Const, and cast parens around Bin
    em = cgen._Emit(Namer())
    assert em.expr(ir.Bin("-", ir.Var("x"), ir.Var("x"))) == "0"
    assert em.expr(ir.Un("(uint8_t)", ir.Bin(">>", ir.Var("v0", "d"), ir.Const(16)))) == "(uint8_t)(v0 >> 0x10)"

    print("ok  test_es_20bit_resolution_and_formatting")


if __name__ == "__main__":
    test_decode_fields()
    test_all_first_bytes()
    test_loop_structuring()
    test_switch_structuring()
    test_coalesce_arithmetic()
    test_global_memory_access()
    test_named_variable_constant()
    test_struct_pointer_cascading()
    test_math_simplification()
    test_brk_and_callt_semantics()
    test_es_20bit_resolution_and_formatting()
    print("\nall tests passed")
