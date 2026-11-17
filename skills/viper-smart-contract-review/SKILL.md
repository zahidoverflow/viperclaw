---
name: viper-smart-contract-review
description: Smart Contract Static Security Auditor (modeled on Slither, Trail of Bits & OpenZeppelin checklists). Reviews Solidity/Rust contracts for reentrancy, access control, ERC-4626, and oracle safety.
---

# ViperClaw Skill 30: Smart Contract Static Security Auditor (`viper-smart-contract-review`)

## Overview
Audits Solidity (EVM) and Rust (Solana/Anchor) smart contracts for common DeFi and protocol vulnerabilities using structured static review checklists.

## Audit Checklist
1. **Reentrancy & Checks-Effects-Interactions (CEI):** Ensure all state variable updates occur *before* external calls (`.call{value: ...}`, ERC-721/ERC-1155 safe transfers) and apply `nonReentrant` guards across shared state.
2. **Access Control & Initialization:** Verify that privileged functions (`mint`, `pause`, `upgradeTo`, `setFee`) enforce `onlyOwner`/`onlyRole` modifiers and proxy implementation contracts call `_disableInitializers()`.
3. **Oracle, Rounding & ERC-4626 Safety:** Check Chainlink `latestRoundData()` for stale timestamps/`answeredInRound`, round division in favor of the protocol, and protect ERC-4626 vaults against first-depositor inflation.
