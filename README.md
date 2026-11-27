# VibeShield Security Gate (`zColdWater/vibeshield-action`)

Zero-dependency pre-launch security gate for AI-built web apps (**Cursor, Lovable, Bolt, v0, Next.js, Vercel, Supabase, Firebase**).

Add 5 lines to your GitHub workflow to audit your live preview or production URL on every pull request — catching exposed client secrets, open Supabase/Firebase tables, missing CSP/HSTS headers, and risky endpoints before users or attackers do.

## Quick Start (1 Step)

```yaml
name: VibeShield Security Gate
on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: write

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Run VibeShield Pre-Launch Audit
        uses: zColdWater/vibeshield-action@v1
        with:
          url: https://yourapp.vercel.app
          fail-below: 75
```

## Example PR Comment

> ### 🟢 VibeShield Security Gate — `yourapp.vercel.app`
>
> | Security Score | Grade | Critical | High | Medium | Low | Gate |
> |:---:|:---:|:---:|:---:|:---:|:---:|:---:|
> | **88 / 100** | **A** | **0** | **0** | 2 | 1 | PASS |
>
> - Posts once and updates in-place (`<!-- vibeshield-security-gate -->`) so it never spams your PRs.
> - **Safe for public repos:** prints severity counts & titles only — never exposes raw keys or sensitive paths in PR logs.
> - Links directly to your **Full Cursor Fix Prompt & 24/7 Monitor** at `https://shipbastion.com` and your public **Verified Trust Page** at `https://shipbastion.com/trust/<domain>`.

## Inputs

| Input | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `url` | Yes | — | Public preview or production URL to scan |
| `fail-below` | No | `0` | Fail CI if score `< fail-below` (`0` = report only) |
| `comment-pr` | No | `true` | Post/update summary comment on Pull Requests |
| `api-base` | No | `https://shipbastion.com` | ShipBastion API origin |
| `github-token` | No | `${{ github.token }}` | Token with `pull-requests: write` for PR comments |

## Outputs

| Output | Description |
| :--- | :--- |
| `score` | Security score (`0-100`) |
| `grade` | Letter grade (`A+` to `F`) |
| `critical-count` | Critical findings count |
| `high-count` | High-severity findings count |
| `report-url` | Live shareable ShipBastion audit URL |
| `trust-url` | Public `Verified by ShipBastion` trust certification URL |

## Full Suite & 24/7 Continuous Monitoring

- **Interactive Scanner & Cursor Auto-Fix Prompt:** https://shipbastion.com
- **Email Deliverability (SPF/DKIM/DMARC):** https://inbox.shipbastion.com
- **AI Search Visibility & Citations (GEO):** https://cite.shipbastion.com
- **Free 78-TLD Domain & USPTO Check:** https://brand.shipbastion.com

## License

MIT
