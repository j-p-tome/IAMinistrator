# Current State

> - 🟢 **AVAILABLE**
> - 🟡 **PARTIAL**
> - 🔴 **UNAVAILABLE**
> - 🔵 **ACTION**

## Verification snapshot
- Repository: `j-p-tome/IAMinistrator`
- **Latest verified commit SHA:** `f2fe798f5dbfcacf66600b51a174fb70ef4a9a47`
- GitHub repo read access this turn: 🟢 **AVAILABLE**
- Space digital twin read access this turn: 🟢 **AVAILABLE**
- Repo write and push-preparation capability: 🟢 **AVAILABLE** (confirmed this turn)

## Files inspected this turn
- `src/cli.rs` (SHA pre-push: `e102aa11a453ab8d70f722bace5f00d3cde40007`)
- `src/commands/user.rs` (SHA pre-push: `46b95fec35114cdee971ad9cfcdcea50e0798c04`)
- `src/utils/output.rs` (SHA pre-push: `fb101d8068618d1002510acde202f7c03b8a1b1c`)
- `src/runtime/graph.rs` (read for pattern reference)
- `src/commands/signin.rs` (read for pattern reference)
- `src/commands/mod.rs` (no change)
- `Cargo.lock`, `Cargo.toml`, `src/main.rs` (directory-listed only)

## Files changed this turn
| File | Change |
|------|--------|
| `src/cli.rs` | Added `RiskInfo { upn: String }` variant to `UserCommands` enum |
| `src/commands/user.rs` | Added `get_user_risk()` fn + match arm for `RiskInfo` |
| `src/utils/output.rs` | Added `print_user_risk_info()` pretty-printer |

## Post-push verification
- `src/commands/user.rs` re-read from GitHub after push: ✅ matches pushed content (SHA `0207038a68d1a6710694241d3b18651470aac451`)

## Graph endpoints used by new feature (verified against MS docs)
- `GET /identityProtection/riskyUsers?$filter=...&$select=userPrincipalName,riskState,riskLevel,riskLastUpdatedDateTime`
- `GET /identityProtection/riskDetections?$filter=...&$orderby=activityDateTime desc&$top=1&$select=activityDateTime,ipAddress,riskState,riskEventType`
- Required permissions: `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All` — both require **Entra ID P2**.

## Required read order before next patch
1. Read relevant Space Markdown files.
2. Read relevant GitHub repo files.
3. Compare and trust GitHub if reachable.
4. For any future user/auth/Graph changes, re-read: `Cargo.toml`, `src/cli.rs`, `src/main.rs`, `src/commands/user.rs`, `src/runtime/graph.rs`, `src/utils/output.rs`.

## Unresolved questions
- `create_user` in `src/commands/user.rs` is still a TODO stub. No action taken.
- `signin:bulk` in `src/commands/signin.rs` is also a TODO stub. No action taken.
- No `perplexity_repo_persistence_instructions.md` file in the repo root. Tracking in `.space/` directory instead.

## If GitHub is unavailable next turn
- Mark Space twin as 🟡 **PARTIAL**.
- Use this file as continuity-only context. Do not present as verified current state.
- Recommend starting a new thread for a fresh repo read.
