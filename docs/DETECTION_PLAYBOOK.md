# Detection Playbook

**Author:** Soubhagya  
**Version:** 1.1  
**Last updated:** 2026-01-28

Operational detection rules mapped to corpus entries in `attacks/`. Rules target indexers, RPC webhooks, wallet telemetry, and SIEM pipelines. Tune thresholds per protocol TVL and traffic baseline.

## Rule format

Each rule includes:

- **Rule ID:** Stable identifier for ticketing integration
- **Corpus mapping:** Primary and secondary entry IDs
- **Data source:** Where signal originates
- **Logic:** Pseudocode or query string
- **Severity:** Alert priority
- **Response:** Recommended analyst action

---

## Initial access and phishing

### DET_001: Fake airdrop claim spike

**Corpus:** `fake_airdrop`  
**Data source:** Token mint indexer, social listening  
**Logic:**

```
COUNT(new_mint WHERE metadata_uri_domain IN threat_intel_feed) > 50 per hour
AND holder_count == 0 at mint time
AND mint_authority != null
```

**Severity:** Medium  
**Response:** Add domain to blocklist; notify wallet partners; trace funding wallet cluster.

### DET_002: NFT phishing domain connect burst

**Corpus:** `nft_phishing_signature`  
**Data source:** Wallet telemetry (opt in), CDN logs  
**Logic:**

```
connect_events WHERE origin_domain age < 7 days
AND similarity(origin_domain, known_protocol_domain) > 0.85
AND sign_request_count > 10 per unique origin per hour
```

**Severity:** High  
**Response:** Block domain in wallet blocklist; publish IOC; preserve transaction samples.

---

## Credential and approval abuse

### DET_003: Unlimited SPL approval

**Corpus:** `unlimited_approve`  
**Data source:** On chain indexer  
**Logic:**

```
Approve instruction WHERE amount == 18446744073709551615
AND delegate_owner NOT IN protocol_allowlist
AND source_wallet_age > 30 days
```

**Severity:** Critical  
**Response:** Push revoke prompt to affected wallets; trace delegate sweep tx.

### DET_004: Token 2022 hook side effect approval

**Corpus:** `token_2022_hook_drain`  
**Data source:** Transaction inner instruction parser  
**Logic:**

```
Token2022 Transfer
AND inner_instruction.type IN (Approve, SetAuthority)
AND inner_program NOT IN token_program_ids
```

**Severity:** Critical  
**Response:** Flag mint; expand hook program bytecode review; alert holders.

---

## Privilege and authority

### DET_005: Mint authority rotation on live asset

**Corpus:** `authority_drain`  
**Data source:** Mint account delta stream  
**Logic:**

```
SetAuthority(MintTokens) WHERE mint_supply > 1000000
AND new_authority NOT IN known_multisigs
```

**Severity:** Critical  
**Response:** Pause market listings; notify exchanges; verify upgrade path.

### DET_006: Stake withdrawer authority change

**Corpus:** `stake_authority_hijack`  
**Data source:** Stake program instruction index  
**Logic:**

```
Authorize(Withdrawer) WHERE stake_lamports > 100 SOL
AND new_authority_first_seen < 24h ago
```

**Severity:** Critical  
**Response:** Contact custodial operator; recommend freeze if central authority exists.

---

## CPI and logic exploits

### DET_007: Same program reentrancy pattern

**Corpus:** `cpi_reentrancy`  
**Data source:** Inner instruction tree  
**Logic:**

```
depth(inner_cpi) >= 2
AND inner_cpi.program_id == outer.program_id
AND token_balance_delta_before_state_update
```

**Severity:** Critical  
**Response:** Circuit breaker pause; fork replay on private cluster; preserve tx signature.

### DET_008: Arbitrary CPI to system program

**Corpus:** `cpi_reentrancy`, `close_account_lamport_theft`  
**Data source:** Program invocation monitor  
**Logic:**

```
victim_program CPI target == System Program
AND instruction NOT IN expected_admin_set
```

**Severity:** High  
**Response:** Compare against IDL allowlist; escalate to protocol team.

---

## Oracle and economic

### DET_009: Oracle price deviation with same slot borrow

**Corpus:** `oracle_manipulation`  
**Data source:** Oracle feed + lending program events  
**Logic:**

```
oracle_price_change > 3 * rolling_std_30min
AND borrow_or_withdraw_same_slot
AND pool_liquidity < 2 * trade_size
```

**Severity:** Critical  
**Response:** Trigger circuit breaker; snapshot oracle accounts; model attacker PnL.

### DET_010: Flash loan governance vote

**Corpus:** `flash_loan_governance`  
**Data source:** Governance + DEX instruction correlation  
**Logic:**

```
vote_weight > 5% total_supply
AND flash_loan_repay_same_transaction
AND proposal_touches_upgrade_authority
```

**Severity:** Critical  
**Response:** Delay timelock execution; community alert; proposal review.

---

## Persistence and upgrade

### DET_011: Program upgrade outside maintenance window

**Corpus:** `program_upgrade_hijack`  
**Data source:** Loader account monitor  
**Logic:**

```
Upgrade instruction on production_program_id
AND NOT scheduled_in_status_page
AND new_buffer_authority != expected_multisig
```

**Severity:** Critical  
**Response:** Halt dependent frontends; diff bytecode; invoke incident bridge.

### DET_012: Metadata mass uri swap

**Corpus:** `metadata_authority_hijack`  
**Data source:** Metaplex instruction index  
**Logic:**

```
UpdateMetadataAccountV2 count > 100 per collection per hour
AND new_uri_domain NOT IN collection_official_domains
```

**Severity:** High  
**Response:** Marketplace delist; verify update authority holder; user comms.

---

## Versioned transactions and simulation gap

### DET_013: ALT mutation near v0 execution

**Corpus:** `alt_lookup_swap`  
**Data source:** Slot aligned ALT + v0 tx monitor  
**Logic:**

```
ExtendLookupTable OR DeactivateLookupTable
AND same_alt_referenced_in_v0_tx_within_slots <= 2
AND token_outflow > threshold
```

**Severity:** Critical  
**Response:** Preserve preview vs execution account diff; wallet vendor notification.

### DET_014: Simulation vs execution account mismatch

**Corpus:** `alt_lookup_swap`, `token_2022_hook_drain`  
**Data source:** Wallet client telemetry  
**Logic:**

```
simulation_account_set != executed_account_set
AND user_approved == true
```

**Severity:** Critical  
**Response:** Incident on wallet team; collect tx signature; user fund tracing.

---

## Cryptographic and replay

### DET_015: Durable nonce replay attempt

**Corpus:** `durable_nonce_replay`  
**Data source:** RPC duplicate submission monitor  
**Logic:**

```
same_message_hash submitted >= 2 times
AND nonce_account unchanged
AND AdvanceNonce NOT first instruction
```

**Severity:** High  
**Response:** Nonce authority rotation; multisig workflow review.

### DET_016: Malleated signature duplicate authorization

**Corpus:** `ed25519_signature_malleability`  
**Data source:** Custom program event log  
**Logic:**

```
same_message_hash AND different_signature_bytes
AND both_verified == true
```

**Severity:** High  
**Response:** Patch verifier; invalidate second authorization; audit historical usage.

---

## Denial of service

### DET_017: Protocol namespace account spam

**Corpus:** `rent_griefing_dos`  
**Data source:** Account creation indexer  
**Logic:**

```
CreateAccount WHERE seed matches protocol_prefix
AND count_per_hour > 10 * baseline
AND owner == attacker_cluster
```

**Severity:** Medium  
**Response:** Enable creation bond; close incentive crank; rate limit keepers.

---

## Account lifecycle

### DET_018: Vault close to external wallet

**Corpus:** `close_account_lamport_theft`  
**Data source:** Token program CloseAccount monitor  
**Logic:**

```
CloseAccount on program_owned_pda
AND lamport_destination NOT IN treasury_allowlist
```

**Severity:** Critical  
**Response:** Emergency pause; verify close instruction authorization path.

### DET_019: Account realloc with role field write

**Corpus:** `account_data_reallocation`  
**Data source:** Program account delta  
**Logic:**

```
account_data_len increase > 50%
AND admin_or_role_field modified same tx
AND signer NOT IN admin_set
```

**Severity:** High  
**Response:** Fork test exploit path; hotfix realloc guards.

---

## Sysvar and validation

### DET_020: Non canonical sysvar address in invoke

**Corpus:** `sysvar_account_spoofing`  
**Data source:** Transaction account metas  
**Logic:**

```
program_invocation accounts named clock
AND account_pubkey != SysvarC1ock11111111111111111111111111111111
```

**Severity:** Critical  
**Response:** Flag program for audit; deny listing; user warning if funds at risk.

---

## Alert tuning guidelines

| Factor | Recommendation |
|--------|----------------|
| TVL < $1M | Raise thresholds 2x to reduce noise |
| TVL > $100M | Enable all Critical rules real time |
| New deployment | First 14 days: lower thresholds 0.5x |
| Known maintenance | Suppress DET_011 with change ticket ID |

## Integration checklist

- [ ] Map rule IDs to PagerDuty services
- [ ] Store corpus entry ID in alert payload
- [ ] Attach attack chain ID from `ATTACK_CHAINS.md` when multi stage confirmed
- [ ] Weekly false positive review with threshold adjustment log
- [ ] Quarterly rule coverage gap analysis against new corpus entries

## Tooling

```bash
# Validate corpus before deploying rule updates
python scripts/validate_corpus.py --verbose

# Regenerate index after new entries
python scripts/render_index.py --output docs/INDEX.md
```
