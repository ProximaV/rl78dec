# Legacy Pure-Python `rl78dec` (Deprecated)

> [!WARNING]
> **`legacy_py/rl78dec/`, `legacy_py/rl78dec_plugin.py`, and `legacy_py/tests/` are deprecated and unmaintained.**
> They are archived here for historical reference only. Use the native C++17 implementation (`rl78dec.dll`, `rl78dec_cli.exe`, `python_sdk/`, and `ctests/`).

## Migrating to Native C++17 `rl78dec`

1. Build and deploy the native IDA Pro 9.5+ plugin and Python SDK from the repository root:
   ```powershell
   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
   cmake --build build --parallel
   cmake --build build --target rl78dec_deploy
   ```
   `rl78dec_deploy` automatically removes legacy `rl78dec_plugin.py` and installs `rl78dec.dll`, `rl78dec_hexrays_bridge.py`, and `python_sdk/rl78dec/` into `%APPDATA%\Hex-Rays\IDA Pro\plugins\`.

2. For headless CLI decompilation, use `rl78dec_cli.exe` instead of `python -m rl78dec`:
   ```powershell
   .\build\rl78dec_cli.exe firmware.bin [-o out.c] [--ea 0xADDR] [--ir]
   ```

3. For Python scripting in IDA, use the C++-backed SDK installed by `rl78dec_deploy` (`python_sdk/rl78dec/` and `ida_hexrays` via `rl78dec_hexrays_bridge.py`).

## Running Archived Legacy Unit Tests (Historical Reference Only)

```powershell
python legacy_py/tests/test_abi.py
python legacy_py/tests/test_pipeline.py
```

