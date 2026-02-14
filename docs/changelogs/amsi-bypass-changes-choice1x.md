# AMSI Bypass Redesign - Research Notes

## Problem
The current `amsiInitFailed` reflection bypass is signature-detected at paste time.
Defender detects the `.GetType().GetField().SetValue()` structural pattern regardless
of string obfuscation on the arguments.

## Detection Vectors (from research doc)
1. String signatures: `AmsiUtils`, `amsiInitFailed`, `Invoke-Mimikatz`
2. Pattern matching: `.GetType(...).GetField(...).SetValue(...)` chain structure
3. Behavioral/ETWti: Runtime modifications to AmsiScanBuffer memory (kernel-level)

## Hypotheses (ranked by CCDC practicality)

### H1: Reflection.Emit DynamicMethod approach [HIGH CONFIDENCE]
- Build the field-set operation via Reflection.Emit IL opcodes
- Reflection.Emit code is NOT scanned by AMSI before execution
- No `.GetType().GetField().SetValue()` pattern in source text
- No disk artifacts (unlike Add-Type)
- Complexity: Medium - need to emit IL that does the equivalent
- Risk: The Reflection.Emit API calls themselves might be signatured
- Confidence: 70%

### H2: Multi-layer encoding with fragment splitting [HIGH CONFIDENCE]
- Split the bypass into 3+ benign fragments
- Each fragment is individually non-malicious
- Assembled and executed at runtime
- Research confirms: "Defender does not effectively correlate fragments
  across separate AMSI scan events within the same session"
- Use XOR or reversed strings (NOT base64 — engines decode that)
- Confidence: 80%

### H3: AMSI Write Raid variant [MEDIUM CONFIDENCE]
- Overwrite AmsiScanBuffer function pointer (memory is R/W, no VirtualProtect needed)
- Published PoC is signatured, but the vulnerability is unpatched
- Requires P/Invoke (GetModuleHandle, ReadProcessMemory, WriteProcessMemory)
- P/Invoke needs Add-Type (disk artifacts) or Reflection.Emit
- More complex, but more robust once working
- Confidence: 60%

### H4: Simple approach - do we even need a bypass? [TEST FIRST]
- Research says: "Set-NetFirewallProfile and similar administrative cmdlets
  are not AMSI-signatured"
- The bypass ITSELF is what's being detected
- If we remove the bypass entirely, does the payload pass?
- If yes: just use runtime string construction for any flagged strings
- Confidence for firewall payload specifically: 50%

## Strategy Decision
Implement H2 (fragment splitting + XOR encoding) as primary approach.
Rationale:
- Highest confidence of working
- No external dependencies (pure PowerShell)
- Fits one-liner constraint perfectly
- Can be generated fresh each time (randomizable)
- Falls back gracefully if it fails (try/catch already in place)

For Layer B (JScript wrapper), use the SAME technique but adapted for
the JScript→PowerShell string escaping context.

## Implementation Plan
1. Create the new Layer A bypass using XOR-encoded fragments
2. Create the new Layer B bypass for JScript wrapper context
3. Update Layer A in the $minimalScript builder (~line 158)
4. Update Layer B encrypted JScript (Build-DeployBlock encrypted path)
5. Update Layer B unencrypted JScript (Build-DeployBlock unencrypted path)
6. Update registry persistence bypass
7. Copy modified file to outputs

## Bypass Architecture

### Fragment-Split + XOR Design

The core idea: instead of writing the `.GetType().GetField().SetValue()` chain
as literal PowerShell, we:

1. XOR-encode each critical string at generation time on Linux
2. Store them as integer arrays in the generated script
3. At runtime, decode and use variable indirection to call the methods
4. Break the reflection chain across multiple IEX calls so no single
   AMSI scan event sees the complete pattern

Specifically, the bypass needs to do:
```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
  .GetField('amsiInitFailed','NonPublic,Static')
  .SetValue($null,$true)
```

We split this into:
- Fragment 1: Get the type object (via decoded string + variable method invocation)
- Fragment 2: Get the field object (via decoded string + variable method invocation)  
- Fragment 3: Set the value

Each fragment individually looks benign to AMSI.

### Key Insight from Research
"Defender does not effectively correlate fragments across separate AMSI
scan events within the same session."

So: `IEX $frag1; IEX $frag2; IEX $frag3` works even when the combined
script would be flagged.

BUT WAIT — we also need to avoid the structural pattern in the SOURCE TEXT.
Even if we split execution, the full source buffer is scanned FIRST.

So the real approach is:
- The source text contains ONLY the XOR-encoded data + decode logic
- The actual reflection calls exist ONLY in decoded runtime strings
- We execute each decoded fragment separately via IEX
- No single scan event (source or IEX) contains the full pattern
