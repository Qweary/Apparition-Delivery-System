# Defeating AMSI in PowerShell for CCDC 2026

**Standard Windows cmdlets like `Set-NetFirewallProfile` are almost certainly not flagged by AMSI signatures — meaning the elaborate AmsiScanBuffer bypass you're building may be unnecessary.** AMSI's signature database targets known offensive tool strings (`Invoke-Mimikatz`, `AmsiUtils`, `amsiInitFailed`) and bypass patterns, not legitimate built-in administration cmdlets. Before implementing complex evasion, test whether your actual payload triggers AMSI at all. If it does — or if your scripts contain genuinely flagged strings — the techniques below are ranked by practicality for a CCDC environment where speed matters more than long-term stealth.

The landscape has shifted significantly since 2024. Defender now uses **ETWti kernel-level behavioral monitoring** to detect AmsiScanBuffer patching, making the classic memory patch approach risky. Newer techniques like the AMSI Write Raid, hardware breakpoints, and ScriptBlock Smuggling represent the current state of the art. The staging approach you proposed (bypass first, payload second) works — but only within the same process.

---

## AMSI scans multiple times, and delivery method doesn't matter

A common misconception is that `-EncodedCommand` adds an extra layer of protection. It doesn't. PowerShell decodes the Base64-encoded UTF-16LE string and then submits the decoded plaintext to `AmsiScanBuffer()` before execution — identical behavior to `-Command` or `-File`. The delivery mechanism is irrelevant to AMSI.

More critically, **AMSI scans at multiple points during execution**. The initial script buffer gets scanned as a whole before any line runs. Then, each call to `Invoke-Expression`, `ScriptBlock::Create()`, or `& ([scriptblock]::Create(...))` generates a separate `AmsiScanBuffer()` call on the content being executed. This means base64-encoding a payload string and decoding it at runtime doesn't fully evade AMSI — the decoded content gets scanned again when passed to IEX.

However, there's an exploitable gap: **Defender does not effectively correlate fragments across separate AMSI scan events within the same session.** Splitting a malicious script into three benign-looking pieces and IEX-ing them separately bypasses detection even when the full script is flagged. This is confirmed by Frida-instrumented analysis of AMSI's scanning behavior.

---

## The simplest techniques that actually work for CCDC payloads

For commands containing standard cmdlet strings, the **call operator with runtime string construction** is the most practical approach:

```powershell
$c = "Set-Net" + "FirewallProfile"; & $c -Enabled $false
```

AMSI scans the source code text, seeing only `"Set-Net"` and `"FirewallProfile"` as separate string literals. The concatenation happens at runtime, after the scan. The `&` operator resolves the command name without submitting it to AMSI as a new script block. This technique consistently defeats string-based signature matching for individual command names.

For payloads requiring multiple suspicious strings, **character-code construction** eliminates all literal strings from the scan buffer:

```powershell
$cmd = -join ([char[]](83,101,116,45,78,101,116,70,105,114,101,119,97,108,108,80,114,111,102,105,108,101))
& $cmd -Enabled $false
```

**Custom encoding (XOR, AES) of the entire payload** goes beyond what AV engines emulate. Base64 is the one encoding format most engines explicitly decode during scanning. A simple XOR with a key, or even just reversing the string, forces AMSI to evaluate only the decoding logic — which is benign. The critical caveat: when you decode and pass the result to IEX, AMSI scans the decoded content. To fully exploit this, combine custom encoding with the fragment-splitting technique — decode and execute pieces separately so no single AMSI scan event contains the complete malicious pattern.

---

## Staging works, but only within one process

Your proposed staging approach is viable and is the standard red team architecture. AMSI operates per-process — once bypassed, all subsequent commands in that process execute without scanning. The correct implementation chains the bypass and payload in a single `powershell.exe` invocation:

```
powershell -Command "[obfuscated_bypass]; [payload]"
```

**Two separate `powershell` invocations will not work** because each creates a new process with fresh `amsi.dll` loaded. The bypass must execute in the same process as the payload.

There are also **two distinct AMSI layers** that require separate bypasses. PowerShell AMSI (via `System.Management.Automation.AmsiUtils`) scans script content and is bypassed by setting `amsiInitFailed=true`. .NET/CLR AMSI (via `clr.dll` calling `AmsiScanBuffer`) scans assemblies loaded via `[System.Reflection.Assembly]::Load()` and requires patching `amsi.dll` directly. For CCDC where you're running PowerShell commands (not loading .NET assemblies), the PowerShell-level bypass is sufficient.

The `amsiInitFailed` reflection bypass still works in 2025 with sufficient obfuscation, but simple string concatenation no longer suffices — Defender uses **regex-like pattern matching** on the structural pattern `.GetType(...).GetField(...).SetValue(...)`. Effective obfuscation requires multi-layer encoding (base64 chunks + format strings + variable indirection) or using **amsi.fail** to generate a fresh, randomly obfuscated bypass snippet for each engagement.

---

## Advanced techniques when simple obfuscation isn't enough

**AMSI Write Raid** (discovered by Victor Khoury at OffSec, April 2024) exploits a fundamental flaw: when .NET's JIT compiler writes the `AmsiScanBuffer` function address into `System.Management.Automation.dll`, it never changes the memory permissions back to read-only. The entry remains Read/Write. This means you can overwrite the function pointer with a dummy address **without calling VirtualProtect** — eliminating the primary behavioral detection signal that Defender monitors. The technique uses `ReadProcessMemory` to locate the writable entry by scanning backwards from `ScanContent`'s address, then overwrites it. It works on both **PowerShell 5.1 and 7.4**. The published PoC is now signatured, but the underlying vulnerability is unpatched and variant implementations remain effective.

**Hardware breakpoint / VEH bypass** is considered the most OpSec-safe approach as of early 2025. It sets CPU debug registers (DR0-DR3) to break on `AmsiScanBuffer` entry, then installs a Vectored Exception Handler that sets RAX to S_OK, writes AMSI_RESULT_CLEAN to the result parameter, and adjusts RIP to skip the function. No memory modifications occur to `amsi.dll` — integrity scanners see nothing. The main limitation is that some EDRs detect `SetThreadContext` calls via ETWti; the **VEH² technique** (by ahkeur) circumvents this by setting hardware breakpoints from within the VEH itself rather than via `SetThreadContext`.

**ScriptBlock Smuggling** (BC Security) is architecturally unique — it exploits the fact that PowerShell ScriptBlocks have separate AST fields for the text representation (what AMSI scans) and the executable code (what runs). By constructing a ScriptBlockAst where these don't match, you submit benign text to AMSI while executing arbitrary code. This also spoofs ScriptBlock logging. Defender now detects the boilerplate pattern as `Trojan:PowerShell/ScriptSmug.A`, but the wrapper code is simpler to obfuscate than an entire malicious payload.

**Reflection.Emit / DynamicMethod** for API access avoids `Add-Type` entirely (which drops temporary `.cs` and `.dll` files to disk via `csc.exe`). The technique uses `Microsoft.Win32.UnsafeNativeMethods` (already loaded in `System.dll`) to resolve `GetModuleHandle` and `GetProcAddress`, then `DefineDynamicAssembly` to create in-memory delegate types for calling `VirtualProtect` and `Marshal.Copy`. Code emitted via `Reflection.Emit` is **not scanned by AMSI** before execution, giving it a distinct advantage over `Add-Type` compiled code.

---

## What Defender actually detects in 2026 and how to avoid it

Defender's AMSI detection operates at three levels. **String/signature matching** flags known malicious strings (`AmsiUtils`, `amsiInitFailed`, `Invoke-Mimikatz`) and byte patterns (the classic `0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3` patch). **Pattern matching** detects structural code patterns even with obfuscated strings — the reflection bypass chain `.GetType().GetField().SetValue()` triggers regardless of how the string arguments are constructed. **Behavioral/ETWti monitoring** detects runtime modifications to `AmsiScanBuffer` memory — this fires from kernel space and cannot be evaded from userland.

The practical detection-avoidance hierarchy for CCDC:

- **Reflection.Emit bypass** avoids disk artifacts and AMSI scanning of emitted code — use this instead of `Add-Type` for any P/Invoke work
- **AMSI Write Raid variants** avoid VirtualProtect calls entirely, sidestepping the primary ETWti behavioral trigger
- **amsiInitFailed with manual obfuscation** still works for PowerShell script scanning; use AMSITrigger to identify exactly which bytes trigger detection and modify only those
- **Hardware breakpoints** leave no memory artifacts but require compiled C# (loadable via the Reflection.Emit approach)
- **String construction + fragment splitting** handles individual cmdlet names without any AMSI bypass at all

For your specific JScript wrapper → PowerShell execution chain: AMSI state does not cross process boundaries. Disabling AMSI in the JScript engine does nothing for the PowerShell process it spawns. Each `powershell.exe` invocation needs its own bypass. The most efficient CCDC pattern is a JScript wrapper that launches `powershell -Command "[fresh_amsi_bypass]; [actual_payload]"` as a single command string.

---

## Conclusion

The most important finding is that your actual problem may not require an AMSI bypass at all — `Set-NetFirewallProfile` and similar administrative cmdlets are not AMSI-signatured. Test your exact payload first. If AMSI does trigger, the **tiered approach** is: try runtime string construction with the `&` operator first (zero-cost, no bypass needed), escalate to a staged `amsiInitFailed` reflection bypass with fresh obfuscation from amsi.fail, and reserve the AMSI Write Raid or hardware breakpoint approach for environments where Defender's behavioral monitoring kills simpler bypasses. The fragment-splitting insight — that Defender doesn't correlate across separate AMSI scan events — is arguably the most operationally useful technique for CCDC, where you control the execution flow and can trivially split payloads into individually benign chunks executed in sequence.
