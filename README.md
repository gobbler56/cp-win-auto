# cp-win-auto — Windows Automation Runner (CyberPatriot Edition)

**Snapshot → Run → Score.**  
Automated, modular hardening for **Windows 11 / Server 2019 / Server 2022** images used in CyberPatriot-style competitions.  
Design priorities: **speed**, **automation**, **determinism**, and **low GUI/ops overhead**.

> This README is future-proofed: it documents the architecture and contracts rather than point-in-time internals, so you can keep evolving modules without rewriting the docs.

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

> Active Directory is **out of scope** for the initial modules; local-only operations are performed unless you add AD-aware modules later.

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

## README intake (OpenRouter-first)

- The parser looks for `README.url` in:
  - `C:\CyberPatriot\README.url`
  - `%PUBLIC%\Desktop\README.url`
  - `%USERPROFILE%\Desktop\README.url`
- It downloads the **ASPX/HTML** page, generates a lightweight **plain-text** view, and sends **both** to OpenRouter.
- The LLM returns **strict JSON** (schema-enforced) with:
  ```json
  {
    "title": "string",
    "all_users": [{"name":"user","account_type":"admin|standard","groups":["g1","g2"]}],
    "critical_services": ["IIS","RDP","SMB","DNS","MySQL","Apache","PHP","FileZilla"]
  }
  ```
- No local regex fallback is used by default (to maximize recall across varied phrasings). If you need an offline mode later, add a second parser module and a profile toggle.

> The model is **selectable** via environment variable. Structured outputs are enforced through **JSON Schema**, preventing “chatty” responses and reducing hallucinations.

---

## User Auditing (implemented now)

This module executes **local** user/account actions using the README as the **source of truth**.

**Order of operations:**

1. **Build allow-lists** from README:
   - `Authorized Users` = all listed users.
   - `Authorized Admins` ⊆ `Authorized Users`.
2. **Create any missing authorized users** (strong random passwords).
3. **Remove unauthorized users by diff**: current local users (minus built-ins) that are not in the allow-list are removed.  
   *Re-enumerate users here.*
4. **Create groups & add members** mentioned in the README (e.g., “create group X and add A,B,C”).
5. **Fix Administrators membership**:
   - Remove locals not in authorized admins (excluding the built-in Administrator SID-500).
   - Ensure all authorized admins are members (create on demand).
6. **Global per-user hardening** (for all non-built-ins):
   - rotate password (strong), **except** the current **auto-logon** user (detected from `Winlogon` keys),
   - enable account,
   - set **password expires**,
   - allow **user can change password**.
7. **Built-ins**:
   - Disable `Guest`,
   - Disable **built-in Administrator** (SID-500), regardless of localized name.

> The module is **idempotent** and will run safely multiple times.

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

> You can also test the module alone: `.\Run-UserAuditing.ps1`.

---

## Modules & contracts

Every module exports:

- `Test-Ready -Context <psobj>` → `$true/$false` (optional).
- `Invoke-Apply -Context <psobj>` → `New-ModuleResult ...`
- `Invoke-Verify -Context <psobj>` (optional, for a non-mutating pass).

`module.json` defines:
```json
{
  "name": "MyModule",
  "category": "CategoryName",
  "priority": 10,
  "appliesTo": { "os": ["win11","server2019","server2022"], "role": ["member","dc"] },
  "dependsOn": [],
  "parallelizable": true
}
```

Add a new module by creating `modules/NN_Category/MyModule/{module.json,MyModule.psm1}`—the engine will auto-discover it.

---

## Profiles & overlays

- `profiles/<os>.json` controls **order** and **toggles** per OS.
- `profiles/overlays/<role>.json` can refine toggles (e.g., kiosk/member/DC).
- You can add new categories or change priority without touching the engine.

---

## Logging & guardrails

- Console output only: `[OK]`, `[!!]`, errors that matter.
- **No GUI automation, no evidence packs**, no background services.
- **Snapshot-first** workflow: revert if needed.
- **Local-only** by default; AD is intentionally not touched unless you add AD modules.

---

## Troubleshooting

- **“OPENROUTER_API_KEY not set”** — set the env var and re-open the shell.
- **“No README.url file found”** — check the default locations or place one at `C:\CyberPatriot\README.url`.
- **Password rotation skipped for auto-logon user** — expected; the module preserves the competition’s auto-logon behavior.
- **Model output errors** — ensure network access and that the selected model id is valid on OpenRouter.

---

## Contributing / extending

- Keep modules **single-responsibility** and **idempotent**.
- Prefer **Windows-native** tooling (`secedit`, `auditpol`, `reg`, `netsh`, `PowerShell`) over GUIs.
- For parsing other categories (services, app configs), extend the OpenRouter schema and wire the resulting fields into new modules.

---

## License

MIT — see `LICENSE`.
