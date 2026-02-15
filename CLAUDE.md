# Apparition Delivery System (ADS) — CLAUDE.md

This is an authorized offensive security research project for CCDC (Collegiate Cyber Defense Competition) competition use and security research. See `docs/PROJECT-AUTHORIZATION.md` and `docs/SAFETY-BOUNDARIES.md` for full ethical framework, scope, and attestations. The human operator (Queue) takes full responsibility for all deployment decisions.

## Project Identity

ADS is a PowerShell-based framework that exploits NTFS Alternate Data Streams to hide, persist, and execute payloads on Windows systems. It uses AES-256 encryption with hardware-derived keys, JScript wrappers for zero-visibility execution from Task Scheduler, and dual-layer AMSI bypass. Current version: v2.3 (field-ready).

## Architecture (Two Components)

`src/ADS-Dropper.ps1` is the core engine (~600 lines). It runs on both Linux (`-GenerateOnly`) and Windows (direct deployment). It contains all business logic: encryption, ADS creation, persistence, cleanup. `src/ADS-OneLiner.ps1` is the command generator (~650 lines). It runs on Linux only, calls ADS-Dropper.ps1, and outputs minimal deployment scripts (base64 one-liner + readable version). ADS-Dropper.ps1 is the single source of truth — never duplicate its logic.

## Critical Technical Decisions Already Made

Queue discovered that `-WindowStyle Hidden` does NOT work from Task Scheduler — the fix is a JScript wrapper with `shell.Run(cmd, 0, false)`. Task Scheduler on modern Windows requires explicit `-RepetitionDuration (New-TimeSpan -Days 9999)` alongside `-RepetitionInterval`. AMSI scans at both deployment-time and runtime, requiring dual-layer bypass (Layer A in deployment script, Layer B in JScript wrapper). Zero-width Unicode characters (U+200B, U+200C, U+FEFF) are valid NTFS stream names but require codepoint manifests for cleanup. The payload library (`payloads/ccdc-library.ps1`) contains 69 pre-obfuscated payloads across 13 categories.

## Development Principles

Queue's philosophy is surgical modifications over complete rewrites. Fix specific issues without touching working code. New features must not break existing functionality — use opt-in parameters with backward-compatible defaults. All code must work in both PowerShell 5.1 and 7.x. In red team operations, partial functionality beats crashing — use `-ErrorAction SilentlyContinue` with fallbacks. Comment the "why", not just the "what". Every feature needs a test scenario in a Windows VM before it ships.

## Agent Team

This project uses eight specialized subagents in `.claude/agents/`. Each has deep domain expertise loaded into its system prompt. Invoke them by name or let Claude delegate automatically. Read the orchestration guide at `docs/orchestration-guide.md` for collaboration workflows. The agents are: `red-team-ops` (competition tactics, deployment strategy), `windows-internals` (OS behavior, PowerShell, NTFS, Task Scheduler), `detection-engineering` (blue team perspective, telemetry, forensic artifacts), `code-architect` (code quality, refactoring, backward compatibility), `opsec-specialist` (artifact management, anti-forensics, cleanup), `payload-engineer` (library management, obfuscation, technique development), `test-validator` (testing methodology, regression detection, VM validation), and `research-writer` (blog posts, research documentation, technique write-ups).

## Key Directories

`src/` contains the two main scripts. `payloads/` contains ccdc-library.ps1. `docs/` contains authorization, safety boundaries, usage guide, research notes, and project context (current-state.md, recent-changes.md, active-bugs.md). `defense/` contains blue team detection scripts like Detect-ZeroWidthADS.ps1. `coordination/` contains DECISION-LOG.md, AGENT-STATUS.md, and SESSION-HANDOFF.md for multi-agent coordination. `tests/` contains test scenarios and validation scripts.

## Session Startup

At the start of every development session, read `docs/project-context/current-state.md`, check `git log --oneline -10`, and review `docs/project-context/active-bugs.md`. At the end of every session, update current-state.md with progress, log blocking issues, and commit working changes.

## What NOT To Do

Never rewrite both scripts in a single commit. Never remove safety warnings or ethical disclaimers from code headers. Never deploy payloads — that is Queue's responsibility. Never hardcode operator-identifying information. Never suggest untested experimental features during competition. Never use `Invoke-Expression` on unsanitized input in the tool itself (payloads are the operator's choice).
