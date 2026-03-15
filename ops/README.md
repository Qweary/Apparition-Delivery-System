# ops/ — Operational Red Team Content

**SENSITIVE: Contains competition strategy, payload library, and deployment materials.**

## Showcase Quick-Start
```bash
# 1. Clone ADS, then clone ops inside it
git clone https://github.com/Qweary/Apparition-Delivery-System
cd Apparition-Delivery-System
git clone https://github.com/Qweary/ops ops

# 2. Generate all showcase scenarios (dry run first)
pwsh ops/red-team-showcase.ps1 -DryRun

# 3. Generate all showcase scenarios for real
pwsh ops/red-team-showcase.ps1 -OutputDir /tmp/showcase/

# 4. Generate with your attacker IP for C2 scenarios
pwsh ops/red-team-showcase.ps1 -AttackerIP 192.168.1.100 -OutputDir /tmp/showcase/

# 5. Generate a single scenario
pwsh ops/red-team-showcase.ps1 -Scenario A1 -OutputDir /tmp/showcase/

# 6. View what was generated
ls -la /tmp/showcase/

# 7. Read the full scenario walkthrough
cat ops/RED-TEAM-SHOWCASE.md
```

## Contents

| Path | Description |
|------|-------------|
| `red-team-showcase.ps1` | Showcase generator — produces all demo one-liners |
| `RED-TEAM-SHOWCASE.md` | Full scenario walkthrough with validation commands |
| `payloads/` | Payload library. `ccdc-library.ps1` (69 payloads, 13 categories). `MEME-PAYLOADS.md` (7 meme payloads, unvalidated). |
| `competition/` | CCDC competition package. Strategy, deployment guide, quick reference, and pre-generated payloads. |

## Quick Links

- **Showcase script:** `ops/red-team-showcase.ps1 -Help`
- **Showcase docs:** `ops/RED-TEAM-SHOWCASE.md`
- **Payload library:** `ops/payloads/ccdc-library.ps1`
- **Meme payloads:** `ops/payloads/MEME-PAYLOADS.md`

## Notes

- `payloads/MEME-PAYLOADS.md` payloads are **unvalidated** — test before competition use
- Depending on instance count, consider resource use.
- Creativity highly encouraged.
