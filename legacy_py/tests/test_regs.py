import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl78dec import isa, regs


def test_atoms_and_pairs():
    assert regs.atoms("ax") == ("x", "a")
    assert regs.atoms("bc") == ("c", "b")
    assert regs.atoms("de") == ("e", "d")
    assert regs.atoms("hl") == ("l", "h")
    assert regs.atoms("sp") == ("spl", "sph")
    assert regs.atoms("a") == ("a",)
    assert regs.atoms("x") == ("x",)
    assert set(regs.atoms("psw")) == {"psw", "cy", "z", "rbs"}

    assert regs.overlaps("ax", "a")
    assert regs.overlaps("ax", "x")
    assert not regs.overlaps("ax", "b")
    assert regs.overlaps("psw", "cy")
    assert not regs.overlaps("sp", "ax")


def test_compose_decompose():
    decomp = regs.decompose("ax", 0x1234)
    assert decomp == {"x": 0x34, "a": 0x12}
    assert regs.compose("ax", decomp) == 0x1234
    assert regs.compose("ax", {"x": 0x34}) is None
    assert regs.compose("a", decomp) == 0x12
    assert regs.compose("x", decomp) == 0x34

    decomp_b = regs.decompose("b", 0x42)
    assert decomp_b == {"b": 0x42}
    assert regs.compose("b", decomp_b) == 0x42


def test_gpr_aliases():
    # RB0 at 0xFFEF8: X, A, C, B, E, D, L, H
    assert regs.gpr_alias(0xFFEF8, "b", 0) == "x"
    assert regs.gpr_alias(0xFFEF9, "b", 0) == "a"
    assert regs.gpr_alias(0xFFEF8, "w", 0) == "ax"
    assert regs.gpr_alias(0xFFEF9, "w", 0) is None  # unaligned
    assert regs.gpr_alias(0xFFEFA, "b", 0) == "c"
    assert regs.gpr_alias(0xFFEFB, "b", 0) == "b"
    assert regs.gpr_alias(0xFFEFA, "w", 0) == "bc"

    # Inactive bank should return None
    assert regs.gpr_alias(0xFFEF8, "b", 1) is None
    # RB1 at 0xFFEF0
    assert regs.gpr_alias(0xFFEF0, "b", 1) == "x"
    assert regs.gpr_alias(0xFFEF1, "b", 1) == "a"
    assert regs.gpr_alias(0xFFEF0, "w", 1) == "ax"

    # Unknown bank
    assert regs.gpr_alias(0xFFEF8, "b", None) is None


def test_special_regs():
    assert regs.special_reg(0xFFFF8, "w") == "sp"
    assert regs.special_reg(0xFFFF8, "b") == "spl"
    assert regs.special_reg(0xFFFF9, "b") == "sph"
    assert regs.special_reg(0xFFFFA, "b") == "psw"
    assert regs.special_reg(0xFFFFC, "b") == "cs"
    assert regs.special_reg(0xFFFFD, "b") == "es"


def test_flag_fx():
    assert isa.FLAG_FX["cmp"] == ("def", "def")
    assert isa.FLAG_FX["inc"] == ("def", None)
    assert isa.FLAG_FX["shl"] == (None, "def")
    assert isa.FLAG_FX["cmp0"] == ("def", "zero")
    assert "incw" not in isa.FLAG_FX
    assert "mulu" not in isa.FLAG_FX


if __name__ == "__main__":
    test_atoms_and_pairs()
    test_compose_decompose()
    test_gpr_aliases()
    test_special_regs()
    test_flag_fx()
    print("ok  test_regs")
