# Reverse-Engineering Notes: `roblox-env.exe` (ExoEnv v0.3.2)

> **⚠️ This is NOT a security audit.**
> These are informal, partial reverse-engineering notes compiled from a single manual
> analysis session using IDA Pro / Hex-Rays. They do **not** constitute a certification
> that this binary is safe, malicious, or anything in between. No dynamic analysis,
> sandboxing, network capture, or full code-coverage review was performed. See
> [Limitations](#limitations--what-this-is-not) before drawing any conclusions.
>
> The author of this document has no affiliation with, and does not own or operate,
> ExoEnv or `roblox-env`.

---

## Target Binary

| | |
|---|---|
| **Filename** | `roblox-env.exe` |
| **ExoEnv Version** | `0.3.2` |
| **SHA256** | `ED7E453381F8273CB1789E0455806B51F3719BCC0410B2DC3406E8C3A34F76B9` |
| **MD5** | `4BB2B2FFF5E95EE2CBF8481A2314C50E` |
| **Size** | `21,715,456 bytes` |
| **Compiler** | Rust, MSVC toolchain (`x86_64-pc-windows-msvc`) |
| **Analyzed with** | IDA Pro (Hex-Rays decompiler) |
| **Analysis date** | 2026-08-09 |
| **Analyst** | Independent / unaffiliated researcher |

These hashes are provided so others can verify they're looking at the exact same
build referenced in this document. **This repository does not redistribute the
binary itself.**

---

## Summary of What Was Observed

This was a manual, exploratory trace starting from the PE entry point and following
the call chain down through Rust's standard runtime initialization. The goal was
simply to understand what the binary does with its command-line argument(s), and
the trace incidentally surfaced some higher-level structural observations. Findings
below are described with the confidence level actually justified by the analysis —
**"appears to" / "consistent with" is used deliberately** where the underlying
evidence is circumstantial rather than fully confirmed.

### Confirmed via static trace

- **Standard MSVC/Rust entry chain.** `start` → `__scrt_common_main_seh` →
  CRT `main` → `std::rt::lang_start_internal` → a compiler-generated `fn main()`
  stub, matching normal Rust-on-Windows binaries with no unusual entry-point
  tampering observed.
- **`fn main()` spawns a secondary thread with a 128 MB stack** (`CreateThread`
  with `dwStackSize = 0x8000000`) before running the bulk of program logic. This
  is a known, benign pattern in some Rust CLI tools/build systems to avoid stack
  overflow on deep recursion; it is not inherently suspicious.
- **The thread is named `"roblox-env-main"`** (an embedded Rust thread-name
  string), consistent with the expected binary name.
- **Uses the `mlua` crate (v0.6.8, per an embedded panic-location string) to
  compile and execute Luau bytecode.** A `luau_compile failed` panic message
  references `mlua-sys-0.6.8\src\luau\luacode.rs`, confirming the Luau
  compiler is `mlua`'s bundled Luau, not a custom/modified VM as far as this
  trace went.
- **References Roblox's public web API.** The string
  `https://games.roblox.com/v1/games` and related field names
  (`userPresences`, `AssetId`, `Creator`, `TargetId`) appear as static data
  referenced from within the main function. This suggests the tool queries
  public Roblox game/asset metadata, but **the actual HTTP call construction,
  what (if anything) is sent, and how the response is used were not traced.**
- **Reads a JSON "profile" file**, located via the `EXOENV_POTASSIUM_PROFILE`
  environment variable if set, otherwise falling back to a default path under
  `%LOCALAPPDATA%` (Windows) referencing a filename containing
  `volt_live_profile.json`. Purpose of this file's contents was not determined.
- **Command-line argument parsing** is implemented as a large, heavily-inlined
  match statement (the compiler unrolled a `match arg { "--flag" => ... }`
  block into per-length XOR/SIMD string comparisons against packed 64-bit
  constants). This is a normal, if aggressive, compiler optimization pattern,
  **not obfuscation added by the developer**, but it made manual flag
  enumeration slow. Not all flags were decoded in this session.

### Not analyzed / explicitly out of scope for this session

- The actual bytecode/behavior of any Luau script the tool loads or executes.
- Full contents and semantics of the ~18,000-line inlined `fn main()` body,
  only representative sections were reviewed, not the whole function.
- Any network traffic actually sent or received at runtime (no dynamic
  analysis or packet capture was performed).
- File system, registry, or process interactions beyond what's described
  above.
- Whether any data (tokens, cookies, user files, etc.) is read, transmitted,
  or exfiltrated.
- Comparison against the tool's published source, if any exists, to check
  for behavioral drift between source and binary.
- Any code paths not reached by static tracing from `main` (e.g., error
  handlers, less obvious branches, anti-debug/anti-analysis checks if present).

---

## Methodology

1. Located the PE entry point (`start`) and manually traced the call chain
   through the MSVC CRT and Rust runtime initialization sequence in IDA's
   disassembly and Hex-Rays pseudocode views.
2. Identified the `CreateThread` call spawning the "real" `fn main()` logic
   and located that function via its vtable-dispatched closure pointer.
3. Attempted full Hex-Rays decompilation of the resulting ~18,000-line
   function; decompilation was partial due to function size/complexity
   (Hex-Rays did not reliably complete a full pass).
4. Reviewed representative sections of available pseudocode and cross-referenced
   embedded strings, panic-location paths, and API/library signatures to
   identify third-party crates and general program structure.
5. No breakpoints were set, the binary was not executed, and no
   instrumentation/hooking was performed - **this was 100% static analysis.**

---

## Limitations / What This Is Not

- **This is not a security audit.** A real audit would include, at minimum:
  dynamic execution in an isolated/instrumented environment, network traffic
  capture and analysis, full code-path coverage (not just what one analyst
  happened to trace in one session), a defined and disclosed methodology,
  and ideally review by more than one independent party.
- **This is not a certification of safety.** Nothing here should be read as
  "this binary is safe to run" or "this binary is malicious." Neither claim
  is supported by the analysis performed.
- **The analyst has no relationship to the ExoEnv project** and cannot
  speak to the intent, trustworthiness, or track record of its developers.
- **Static analysis of Rust binaries is inherently incomplete.** Aggressive
  inlining and optimization (as seen here) can obscure logic that would be
  much clearer with source access or dynamic tracing.
- Findings reflect **one specific build** (identified by the hashes above).
  They say nothing about other versions.

If you are trying to decide whether to run this binary, these notes may be
one small data point, but they are not a substitute for your own risk
assessment appropriate to your threat model.

---

## Reproducing This Analysis

Anyone with a copy of the exact binary (verify via the SHA256/MD5 above) can
reproduce the static trace using IDA Pro / Hex-Rays or an equivalent
disassembler, starting from the PE entry point and following the call chain
described in [Methodology](#methodology). No proprietary tooling or private
data was used.

### Personal Notes:
From everything I have seen in this code I believe ExoEnv roblox-env.exe for version 0.3.2 to be safe. This is my own personal opinion and should not be included in your own personal decision as to whether or not this binary is malicious or not. The exact Reverse Engineering findings point to that this specific binary doesn't do anything malicious and the binary is not packed or obfuscated in any way. The import and export tables are clear and there is no evidence of import/export spoofing/fuzzing.
