# cp-win-auto — Windows Automation Runner

Automated, modular hardening for **Windows 11 / Server 2019 / Server 2022** images used in CyberPatriot.  

---

## What this project does

- **Runs headless** hardening and scoring actions, orchestrated by a small engine.
- **Parses the README (ASPX/HTML) via OpenRouter** to extract the authoritative user/admin/groups picture and any high-signal service hints.
- **Applies category modules** in a defined order. Each module is independent; the engine will happily run if only one module exists.
- **Assumes snapshot + revert** is your safety net. No evidence packs, no GUI work, no long logs—just fast actions.

---

## Supported targets

- Windows 11 (client)
- Windows Server 2019 / 2022 (Desktop Experience)

---

## High-level architecture

```
Run.ps1
└─ core/
   ├─ Engine.psm1        # loads modules, builds context, orders execution
   ├─ Parsing.psm1       # fetches README via .url, calls OpenRouter, normalizes output
   ├─ NLP.OpenRouter.psm1# OpenRouter client with JSON Schema enforcement
   ├─ Utils.psm1         # user/group/helpers, password gen, autologon detection, etc.
   └─ Contracts.psm1     # New-ModuleResult()
└─ modules/
   ├─ 01_UserAuditing/   # fully implemented (local)
   └─ ...                # other categories; can be added anytime
└─ profiles/             # per-OS order/toggles; overlays for roles
└─ assets/               # baselines, GPO, firewall, lists (optional inputs)
```

**Engine flow** (simplified):
1. Detect OS, build context.
2. **Parse README** (URL → HTML → OpenRouter) to structured data.
3. Load the per-OS **profile** (module order + toggles).
4. Discover and execute modules.

---

## Environment & prerequisites

- **Administrator PowerShell** (Windows PowerShell 5.1 is fine).
- **Internet connectivity** to reach OpenRouter.
- Environment variables:
  - `OPENROUTER_API_KEY` — required.
  - `OPENROUTER_MODEL` — optional; defaults to a strong extraction model. You can switch models without code changes.

Example (per-session):
```powershell
$env:OPENROUTER_API_KEY = "sk-or-..."
$env:OPENROUTER_MODEL   = "openai/gpt-5-mini"   # or another supported model id
```

Example (persist):
```powershell
setx OPENROUTER_API_KEY "sk-or-..."
setx OPENROUTER_MODEL   "openai/gpt-5-mini"
```

---

## Quick start

1. **Snapshot** the VM.
2. Open **elevated PowerShell** in the repo root:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\Run.ps1 -Mode Apply -Profile Auto
   ```
3. Watch for `[OK]` lines as actions apply.

> You can also test individual modules in interactive mode: `.\Run.ps1 -Mode Apply -Interactive`.

---

## Troubleshooting

- **“OPENROUTER_API_KEY not set”** — set the env var and re-open the shell.
- **“No README.url file found”** — check the default locations or place one at `C:\CyberPatriot\README.url`.
- **Password rotation skipped for auto-logon user** — expected; the module preserves the competition’s auto-logon behavior.
- **Model output errors** — ensure network access and that the selected model id is valid on OpenRouter.

---

## License

MIT — see `LICENSE`.
