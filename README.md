# rl78dec — a Renesas RL78 decompiler

`rl78dec` decompiles Renesas **RL78** firmware to readable pseudo-C, aimed at the
PlayStation 4/Vita **syscon** (system controller) whose MCU is an RL78. It is the
RL78 analogue of [`spudec`](https://github.com/zecoxao/spudec) and the Kirk/Spock
[`startrekdec`](https://github.com/zecoxao/startrekdec): the IDA processor module
is used purely as a *decoder*, and lifting, control-flow recovery and code
generation are ours.

```
decoder → lifter → cfg → frame → spill → opt → abi → vars → structure → cgen
```

## What it produces

```c
uint16_t process_external_cmd(uint16_t arg_4, uint8_t arg_6)
{
    uint16_t var_6;
    uint16_t var_2;
    uint16_t v0;
    uint16_t v1;
    uint16_t v2;
    uint16_t v3;
    uint16_t v4;
    uint16_t v5;
    uint16_t v6;
    uint16_t v7;

    v1 = arg_4;
    v2 = arg_4;
    a = arg_6;
    es = arg_6;
    v3 = 0;
    es_mem16[arg_4 + 4] = 0;
    var_2 = 0;
    sub_8999();
    v0 = 0;
    v4 = v0;
    var_6 = v0;
    v5 = var_2;
    if (var_2 < var_6) JUMPOUT(0x0882F);
    v6 = 7;
    set_jig_device_state_3_7(7);
    v7 = 1;
    return 1;
}
```

Computational registers are elevated to virtual C variables (`v0`, `v1`, …) with
automatic type deductions (`uint16_t`, `uint8_t`) declared at the top of the function;
live-in entry registers bind to parameters (`a0`, `a1`). Stack spills (`push r` / `pop r'`)
used to preserve a register are eliminated, uncoupling variable lifetimes from machine registers.
Direct memory accesses and indexed buffer/array operations resolve to named global symbols
(`byte_FFE50`, `word_FFE4C[v0] = word_FFE48[v0]`), replacing synthetic `mem16[...]`/`mem8[...]`
constructs. Documented SFRs and saddr cells appear by name (`WDTE`, `P4`,
`MK0L`, …). `cmp`/`cmp0` fold into relational `if`s (CY/HF compares are
unsigned), the RL78 *skip* idiom (`skz`/`skc`/…) becomes a one-instruction `if`,
multi-way branches recover as clean C `switch` statements with `break`/`return`,
loops are recovered as `while`/`do-while`, and cross-function tail jumps render
as `JUMPOUT(addr)`.

### Stack frame and calling convention recovery

Renesas RL78 compilers (CA78K0R and CC-RL) establish a frame pointer in `HL`
(`movw hl, sp`) after allocating local stack space (`subw sp, #N` and callee-saved pushes).
Function arguments are passed in `AX` (1st parameter), `BC` (2nd parameter), and pushed on
the stack (3rd+ parameter). Return values are returned in `AX`, `BC`, `A`, `C`, or `CY`.

`rl78dec` automatically:
* **Suppresses prologue & epilogue boilerplate**: Callee-saved register pushes/pops (`HL`, `DE`, `BC`), stack allocation/deallocation (`subw sp, #N` / `addw sp, #N`), and frame pointer setup (`movw hl, sp`) are filtered out.
* **Resolves stack variables**: Accesses via `[hl + disp]` and `[sp + disp]` are mapped to local variables (`var_X`) and incoming stack arguments (`arg_X`), reusing IDA's frame analysis definitions when run in IDA or deriving offsets headlessly.
* **Declares local variables**: Variable declarations (`uint16_t var_X;`, `uint8_t var_X;`) are placed at the head of the function body.
* **Infers function signatures**: Backwards dataflow liveness analysis determines incoming register arguments (`a0`, `a1`) and return types (`uint16_t`, `uint8_t`, `bool`, `void`) with return expressions (`return val;`).
* **Recovers call-site arguments**: Call instructions capture arguments setup before the call (`callee(arg0, arg1)`) and fold return values into receiving assignments (`dst = callee(...)`).

### High-level virtual variable recovery and spill elimination

Microcontroller compilers for the 16-bit RL78 routinely spill registers to temporary stack slots (`push r ... pop r'`) to save values during inner calculations, and reuse the small set of 4 register pairs (`AX`, `BC`, `DE`, `HL`) across unrelated code blocks. A decompiler can have an arbitrary number of variables independent of machine registers.

`rl78dec` implements a high-level variable layer above the register machine:
* **Global Reaching Definitions**: Iterative CFG dataflow analysis tracks definitions and uses of all general-purpose register atoms (`a`, `x`, `b`, `c`, `d`, `e`, `h`, `l`) and temporary stack spill slots.
* **Def-Use Web Construction**: Using Union-Find, definitions and uses that reach each other are grouped into connected live-range webs. Disjoint reuses of the same register become independent virtual variables (`v0`, `v1`, ...).
* **Abstract Stack Spill Elimination**: Stack pushes and pops inside function bodies (`push de ... pop ax`) are bridged into variable dataflow, completely removing `push(...)` and `pop(...)` intrinsics and temporary spill slots (`_s0`).
* **Loop Induction Recovery**: Defs and updates around loop headers are unified across CFG edges into single, clean loop induction variables (`v0 = 4; do { v0 = v0 - 1; } while (v0 != 0);`).
* **Parameter Binding**: Live-in entry register webs are bound directly to parameter names (`a0`, `a1`) instead of machine register aliases.
* **Single-Use Inlining & Dead-Store Elimination**: Pure single-use temporaries are inlined into their use sites, and redundant identity assignments (`v = v`) or dead stores are culled.
* **Typed Declarations**: Virtual variables (`uint16_t v0; uint8_t v1;`) are declared with deduced widths at the head of the function.

### Switch statement and jump table recovery

RL78 switch statements typically compile to an indirect branch (`br ax`) indexed
through an in-memory jump table embedded in flash (32-bit far pointer table with CS
segment byte or 16-bit near pointer table). In IDA Pro, these target blocks are
often split into detached "function fragments".

`rl78dec` automatically:
* Identifies jump tables and their case bounds directly from flash or via IDA's `switch_info_t`.
* Reconstructs the original switch variable and omits compiler table-lookup boilerplate.
* Groups multi-case targets and recovers `break` and `return` semantics.
* Pulls fragmented target blocks into the parent function's CFG, avoiding stub functions.
* When navigating in IDA, pressing `Ctrl-Shift-S` on any fragment of a switch automatically decompiles the parent function.

```c
void sub_D34E(void)
{
    a = a & 0x1F;
    a = a - 1;
    switch (a) {
    case 0:
    case 1:
        return;
    case 2:
        push(bc);
        c = c << 1;
        ax = es_mem16[0x0DDC6 + c];
        a = 0;
        ax = ax + 0xDE13;
        de = ax;
        pop(bc);
        break;
    case 3:
        c = c << 1;
        ax = es_mem16[0x0DDC6 + c];
        a = 0;
        ax = ax + 0xDE1F;
        de = ax;
        a = 0xFF;
        es_mem8[de] = 0xFF;
        return;
    ...
    }
}
```

## Two ways to run it

**Headless (no IDA)** — a raw flash dump or a Sony FUPD container:

```
python -m rl78dec syscon.bin -o syscon.c
python -m rl78dec syscon.bin --func 0x7EB1        # one function
python -m rl78dec syscon.bin --entry 0x1234       # extra entry point
```

Entry points are taken from the interrupt/reset vector table; the decoder then
follows direct calls and switch targets. PS4 syscon dumps can be found in the
community (e.g. the darthsternie firmware archive); they are **not** included here.

**As an IDA plugin** — open the dump with fail0verflow's
[RL78 processor module](https://github.com/fail0verflow/rl78-ida-proc), then drop
`rl78dec_plugin.py` **and** the `rl78dec/` package into
`%APPDATA%\Hex-Rays\IDA Pro\plugins\`:

| Hotkey | Action |
| --- | --- |
| `Ctrl-Shift-S` | decompile the function under the cursor |
| `Ctrl-F5` | decompile the whole database (and offer to save it) |
| `N` | rename variable, argument, or function under cursor |
| `Y` | set variable type or function prototype (IDA type system) |
| `Tab` | toggle sync with disassembly (follows cursor across functions) |
| `Enter` / `Space` | jump to address in disassembly view |
| `F5` | refresh decompilation |

The interactive viewer is dockable, syntax-highlighted with IDA's theme colors,
features right-click context actions, and double-click navigation. User renames,
type overrides, function prototypes, and sync preferences are persisted directly
within the IDA database (`.idb`/`.i64`) via IDA netnodes (`$ rl78dec`), surviving
across IDA sessions.

## The instruction set & optimizations

RL78 (S1/S2 core): little-endian, variable length (1–4 bytes, plus the optional
`0x11` **ES:** far-data prefix), with three secondary opcode maps (`0x31`,
`0x61`, `0x71`). Registers `X A C B E D L H` (and pairs `AX BC DE HL`), SFRs at
`0xFFF00+`, saddr at `0xFFE20+`.

* **Full ALU & Opcode Coverage**: 100% instruction decode across full production
  firmware dumps (all 256 root opcodes + extended maps, including `xch a, reg`).
* **Register Bank & Alias Tracking**: Tracks active register banks (`RB0`..`RB3` via
  `sel rbN`) and canonicalizes memory-mapped GPR accesses (`0xFFEE0..0xFFEFF`).
* **Atom-Level Constant & Copy Propagation**: Decomposes 16-bit register pairs into
  high/low byte atoms, tracking individual 8-bit updates and composing 16-bit reads.
* **Flag Provenance**: Synthesizes natural comparison expressions (`a == 0`, `a != c`,
  `b < 10`) from `cmp`, `sub`, `cmp0`, and status flag updates.
* **Intrinsics**: Rotates, string ops, stack, swap (`SWAP(a, b)`), and CPU-control
  instructions that do not map cleanly onto C are printed as clear intrinsics.

## Limitations

* Only the S1/S2 instruction set the fail0verflow module covers (no S3
  multiply/divide/MAC).
* Entry discovery follows direct calls and switch tables; indirect calls (`call ax`)
  need seeding with `--entry` if not reached via calls.

## Tests

```
python tests/test_frame.py
python tests/test_abi.py
python tests/test_spill.py
python tests/test_vars.py
python tests/test_db.py
python tests/test_pipeline.py
python tests/test_regs.py
python tests/test_highlight.py
```

Hand-assembled and headless, so they need neither IDA nor a firmware dump: they
check stack frame recovery and boilerplate suppression, calling convention and
parameter/return analysis, abstract stack simulation and spill elimination,
global reaching-definitions variable recovery and parameter binding, decoder
field extraction, that every opcode decodes without raising, register bank
aliasing, arithmetic and constant propagation, switch statement structuring,
loop recovery as `do/while`, and the token highlighter.

## Credits

Built on the RL78 reverse-engineering of fail0verflow (processor module, syscon
loader) and astrelsky/hedgeberg (Ghidra SLEIGH). Decompiler design mirrors
zecoxao's `spudec`. MIT licensed. No firmware is included.
