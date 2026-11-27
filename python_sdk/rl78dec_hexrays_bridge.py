"""Lightweight IDAPython bootstrapper for `rl78dec` Hex-Rays (`ida_hexrays`) compatibility.

On Renesas RL78 / 78K0R databases (`PH.id == 0x8078` or `rl78` processor),
installs the `rl78dec` dynamic `ida_hexrays` compatibility proxy automatically
so generic IDAPython scripts and MCP tools (`import ida_hexrays; ida_hexrays.decompile(ea)`)
work seamlessly without requiring `import rl78dec` first.

On all non-RL78 architectures (x86, x64, ARM, PPC, SPU, etc.), returns
`PLUGIN_SKIP` (`None`) immediately without importing `rl78dec` or touching `ida_hexrays`.
"""

import ida_idaapi
import ida_idp


def _is_rl78_proc() -> bool:
    try:
        if ida_idp.ph_get_id() == 0x8078:
            return True
        name = ida_idp.get_idp_name() or ""
        return name.lower().startswith("rl78")
    except Exception:
        return False


class _Rl78HexraysBridgePlugmod(ida_idaapi.plugmod_t):
    def run(self, _arg):
        return True


class _Rl78HexraysBridgePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_MULTI
    comment = "rl78dec ida_hexrays compatibility bridge (RL78 only)"
    help = ""
    wanted_name = "rl78dec_hexrays_bridge"
    wanted_hotkey = ""

    def init(self):
        if not _is_rl78_proc():
            return None
        try:
            import rl78dec.hexrays_compat as hxc
            hxc.install_hexrays_compat()
        except Exception as exc:
            print(f"[rl78dec] Failed to install ida_hexrays bridge: {exc}")
        return _Rl78HexraysBridgePlugmod()


def PLUGIN_ENTRY():
    return _Rl78HexraysBridgePlugin()
