"""
Renesas RL78 instruction-set description.

The RL78 (S1/S2 core) is a 16-bit Renesas microcontroller; it is the CPU inside
the PlayStation 4/Vita "syscon" system controller, which is what these tools target.
This module is the single source of truth for register names, the flag effects of
each mnemonic, and the memory-map helpers.  The decoder in
:mod:`rl78dec.decoder` is a faithful port of fail0verflow's IDA processor module
(``rl78-ida-proc``, based on Renesas R01US0015EJ0220); the lifter follows
astrelsky's Ghidra SLEIGH semantics (``RL78_sleigh``).

Memory map (20-bit address space):
    0x00000..0x7FFFF   code flash (cflash)
    0xF0000..0xFFEFF   RAM / mirror
    0xFFE20..0xFFF1F   saddr short-addressing area
    0xFFF00..0xFFFFF   SFRs (special function registers)
"""

# 8-bit registers in encoding order (index 0..7).
R8 = ("x", "a", "c", "b", "e", "d", "l", "h")
# 16-bit register pairs in encoding order (index 0..3).
R16 = ("ax", "bc", "de", "hl")
# register banks
RB = ("rb0", "rb1", "rb2", "rb3")

WORD_REGS = frozenset(R16 + ("sp",))


def sfr_abs(rel):
    return 0xFFF00 + rel


def saddr_abs(rel):
    addr = 0xFFE00 + rel
    if rel < 0x20:
        addr |= 1 << 8
    return addr


# ---------------------------------------------------------------------------
# flag effects  --  which mnemonics set Z / CY, for branch-condition recovery
# ---------------------------------------------------------------------------
# RL78 conditional branches read CY (bc/bnc), Z (bz/bnz) and CY|Z (bh/bnh).
# Mapping: mnem -> (Z_effect, CY_effect)
#   Z_effect:  "def" (sets Z from result/cmp), None (preserves Z)
#   CY_effect: "def" (sets CY from carry/borrow/shift), "zero" (clears CY to 0), None (preserves CY)
FLAG_FX = {
    # Z & CY
    "add":   ("def", "def"),
    "addc":  ("def", "def"),
    "sub":   ("def", "def"),
    "subc":  ("def", "def"),
    "addw":  ("def", "def"),
    "subw":  ("def", "def"),
    "cmp":   ("def", "def"),
    "cmpw":  ("def", "def"),
    "cmps":  ("def", "def"),
    "movs":  ("def", "def"),
    # Z only
    "and":   ("def", None),
    "or":    ("def", None),
    "xor":   ("def", None),
    "inc":   ("def", None),
    "dec":   ("def", None),
    # CY only
    "shl":   (None, "def"),
    "shr":   (None, "def"),
    "sar":   (None, "def"),
    "shlw":  (None, "def"),
    "shrw":  (None, "def"),
    "sarw":  (None, "def"),
    "ror":   (None, "def"),
    "rol":   (None, "def"),
    "rorc":  (None, "def"),
    "rolc":  (None, "def"),
    "rolwc": (None, "def"),
    "set1":  (None, "def"),
    "clr1":  (None, "def"),
    "not1":  (None, "def"),
    "mov1":  (None, "def"),
    "and1":  (None, "def"),
    "or1":   (None, "def"),
    "xor1":  (None, "def"),
    # CY:=0, Z
    "cmp0":  ("def", "zero"),
}

SETS_Z = frozenset(m for m, (z, _) in FLAG_FX.items() if z == "def")
SETS_CY = frozenset(m for m, (_, cy) in FLAG_FX.items() if cy is not None)

# instructions that end a basic block (unconditional flow / return)
STOP = frozenset(("br", "ret", "reti", "retb", "brk", "stop"))
RET = frozenset(("ret", "reti", "retb"))
# conditional PC-relative branches: mnemonic -> flag-condition token
COND_BRANCH = {
    "bc": ("cy", True),     # branch if CY==1
    "bnc": ("cy", False),
    "bz": ("z", True),
    "bnz": ("z", False),
    "bh": ("h", True),      # branch if higher (unsigned >)
    "bnh": ("h", False),
}
# bit-test branches
BIT_BRANCH = frozenset(("bt", "bf", "btclr"))
# skip-next-instruction idioms: mnemonic -> (flag, sense)
SKIP = {
    "skc": ("cy", True),
    "sknc": ("cy", False),
    "skz": ("z", True),
    "sknz": ("z", False),
    "skh": ("h", True),
    "sknh": ("h", False),
}
CALL = frozenset(("call", "callt"))
