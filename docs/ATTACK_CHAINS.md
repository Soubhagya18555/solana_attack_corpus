# Attack Chains on Solana

**Author:** Soubhagya  
**Version:** 1.1  
**Last updated:** 2026-01-28

This document maps multi-step adversary workflows that combine corpus entries in `attacks/`. Single instruction exploits are rare at scale; profitable attacks chain initial access, privilege gain, asset movement, and laundering.

## Chain taxonomy

| Chain ID | Name | Primary objective | Typical duration |
|----------|------|-------------------|------------------|
| CHAIN_01 | Wallet drain via approval | Steal SPL holdings | 1 transaction |
| CHAIN_02 | Governance capture | Protocol parameter control | 1 block to 7 days |
| CHAIN_03 | Oracle to vault | Lending or perps insolvency | 1 transaction |
| CHAIN_04 | Upgrade persistence | Long term backdoor | Days to months |
| CHAIN_05 | NFT social lure | Collectible and SOL theft | Minutes |
| CHAIN_06 | ALT preview swap | Bypass wallet simulation | 1 to 3 slots |
| CHAIN_07 | Token 2022 hook cascade | Delegate then sweep | 1 to 2 transactions |
| CHAIN_08 | Stake authority pivot | Convert stake to liquid theft | Hours to epochs |

## CHAIN_01: Wallet drain via approval

**Goal:** Obtain unlimited token delegate then sweep all ATAs.

```
fake_airdrop --> unlimited_approve --> authority_drain (sweep CPI)
```

### Stage breakdown

1. **Initial access (`fake_airdrop`)**  
   Victim receives worthless token or DM with claim link. Fake site mimics Jupiter or Raydium styling.

2. **Credential access (`unlimited_approve`)**  
   Transaction requests `Approve` with u64::MAX delegate amount to drainer program owned ATA manager.

3. **Collection (`authority_drain`)**  
   Attacker invokes `TransferChecked` as delegate across all victim ATAs without further signatures.

### Detection pivot points

| Stage | Signal | Response |
|-------|--------|----------|
| Airdrop | Unknown mint with transfer hook extension | Hide token, warn user |
| Approve | Delegate set to non allowlisted program | Block sign |
| Sweep | Multiple TransferChecked from victim ATAs | Auto revoke delegate tooling |

### Related corpus entries

`fake_airdrop`, `unlimited_approve`, `authority_drain`, `token_2022_hook_drain`

---

## CHAIN_02: Governance capture via flash liquidity

**Goal:** Pass malicious proposal controlling upgrade authority or treasury.

```
flash_loan_governance --> program_upgrade_hijack --> authority_drain
```

### Stage breakdown

1. **Privilege escalation (`flash_loan_governance`)**  
   Borrow governance token via flash loan, vote, return loan in same transaction.

2. **Persistence (`program_upgrade_hijack`)**  
   Passed proposal points upgrade authority to attacker multisig or executes malicious upgrade instruction.

3. **Impact (`authority_drain`)**  
   Upgraded bytecode mints unbacked tokens or redirects vault PDAs.

### Mitigation chain

- Vote snapshot at proposal creation block, not execution block.
- Timelock on passed proposals exceeding 48 hours.
- Upgrade authority behind independent multisig not controlled by token vote contract.

---

## CHAIN_03: Oracle manipulation to vault drain

**Goal:** Borrow or withdraw against inflated collateral price.

```
oracle_manipulation --> cpi_reentrancy --> close_account_lamport_theft
```

### Stage breakdown

1. **Impact setup (`oracle_manipulation`)**  
   Manipulate TWAP or spot oracle within confidence interval using thin pool swaps.

2. **Defense evasion (`cpi_reentrancy`)**  
   Reenter lending pool withdraw handler before collateral balance updated.

3. **Cleanup (`close_account_lamport_theft`)**  
   Close ephemeral accounts redirecting rent and dust to attacker consolidation wallet.

### On chain correlation query

```
oracle_price_delta > 3_sigma
AND borrow_instruction
AND inner_cpi_same_program
AND close_account_destination = collector_wallet
```

---

## CHAIN_04: Upgrade persistence backdoor

**Goal:** Maintain arbitrary code execution after audit window.

```
program_upgrade_hijack --> sysvar_account_spoofing --> account_data_reallocation
```

### Stage breakdown

1. Attacker gains upgrade authority via leaked key or governance chain.
2. Deploys bytecode trusting user supplied sysvar accounts (`sysvar_account_spoofing`).
3. Uses realloc to widen admin config account without migration guard (`account_data_reallocation`).

### Forensic timeline artifacts

| Artifact | Where to find |
|----------|---------------|
| Upgrade tx signature | Program loader account history |
| Pre/post bytecode hash | `solana program dump` diff |
| First malicious invoke | Inner instruction trace on drain tx |

---

## CHAIN_05: NFT social lure

**Goal:** Steal NFTs and SOL via deceptive signing.

```
nft_phishing_signature --> metadata_authority_hijack --> unlimited_approve
```

### Stage breakdown

1. User signs listing or mint transaction that includes hidden delegation (`nft_phishing_signature`).
2. Attacker updates metadata uri to counterfeit artwork (`metadata_authority_hijack`).
3. Secondary drain via token delegate on paired SPL holdings (`unlimited_approve`).

---

## CHAIN_06: ALT preview swap

**Goal:** Execute different accounts than wallet preview displayed.

```
alt_lookup_swap --> cpi_reentrancy --> token_2022_hook_drain
```

### Critical timing window

```
Slot N:   User previews v0 tx, ALT index 2 = Raydium pool
Slot N+1: Attacker ExtendLookupTable, index 2 = drainer program
Slot N+1: User signed tx executes with swapped resolution
```

**Wallet requirement:** Re-resolve ALT at sign and broadcast. Pin table content hash in audit log.

---

## CHAIN_07: Token 2022 hook cascade

**Goal:** Hide delegate grant inside transfer hook CPI.

```
fake_airdrop --> token_2022_hook_drain --> unlimited_approve
```

Spam Token 2022 mint with malicious hook. User "claims" or sends token triggering hook CPI that approves drainer. Second transaction sweeps via delegate.

---

## CHAIN_08: Stake authority pivot

**Goal:** Redirect staked SOL to attacker validator then withdraw.

```
stake_authority_hijack --> durable_nonce_replay --> authority_drain
```

Phishing site requests Authorize for "APY boost." Attacker rotates withdrawer, uses durable nonce to replay partial multisig, exits stake to consolidation wallet.

---

## Chain coverage matrix

| Corpus entry | CHAIN_01 | CHAIN_02 | CHAIN_03 | CHAIN_04 | CHAIN_05 | CHAIN_06 | CHAIN_07 | CHAIN_08 |
|--------------|:--------:|:--------:|:--------:|:--------:|:--------:|:--------:|:--------:|:--------:|
| fake_airdrop | x | | | | x | | x | |
| unlimited_approve | x | | | | x | | x | |
| authority_drain | x | x | | x | | | | x |
| flash_loan_governance | | x | | | | | | |
| program_upgrade_hijack | | x | | x | | | | |
| oracle_manipulation | | | x | | | | | |
| cpi_reentrancy | | | x | | | x | | |
| nft_phishing_signature | | | | | x | | | |
| metadata_authority_hijack | | | | | x | | | |
| alt_lookup_swap | | | | | | x | | |
| token_2022_hook_drain | | | | | | | x | |
| stake_authority_hijack | | | | | | | | x |
| durable_nonce_replay | | | | | | | | x |
| sysvar_account_spoofing | | | | x | | | | |
| account_data_reallocation | | | | x | | | | |
| close_account_lamport_theft | | | x | | | | | |
| ed25519_signature_malleability | | | | | | | | |
| rent_griefing_dos | | | | | | | | |

## Using chains in incident response

1. Identify **terminal impact instruction** (transfer, mint, upgrade).
2. Walk backward through inner CPIs and preceding transactions in same slot.
3. Match each stage to corpus entry indicators in `DETECTION_PLAYBOOK.md`.
4. Document chain ID in post incident report for regression testing.

## References

- Corpus taxonomy: `TAXONOMY.md`
- Investigation procedure: `METHODOLOGY.md`
- Detection rules: `DETECTION_PLAYBOOK.md`
