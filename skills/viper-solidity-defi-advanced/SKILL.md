---
name: viper-solidity-defi-advanced
description: Advanced DeFi Protocol, Oracle, EIP-712 & Cross-Chain Bridge Auditor (modeled on Trail of Bits, Cyfrin & Immunefi). Reviews flash-loan TWAPs, EIP-712 replay, and read-only reentrancy.
---

# ViperClaw Skill 63: Advanced DeFi, EIP-712 & Cross-Chain Bridge Auditor (`viper-solidity-defi-advanced`)

## 1. Standards & Open-Source Reference
- **Standards:** Trail of Bits `building-secure-contracts`, OpenZeppelin Contracts v5, Immunefi Top DeFi Vulnerability Taxonomy.
- **Focus:** Auditing AMMs, lending markets, staking/yield vaults, EIP-712/EIP-2612 permit signatures, and cross-chain bridges.

## 2. Rapid Discovery Patterns
- Search `*.sol` for `ecrecover`, `DOMAIN_SEPARATOR`, `getReserves()`, `balanceOf(address(this))`, `latestRoundData()`, `delegatecall`.

## 3. Technical Audit Checklist
1. **Flash-Loan Spot Price & `balanceOf(address(this))` Manipulation:** Never compute collateral value or share price from instantaneous AMM spot reserves (`pair.getReserves()`) or raw `token.balanceOf(address(this))` (vulnerable to flash-loan and direct-donation manipulation). Use manipulation-resistant Chainlink feeds + TWAP or internal accounting balances.
2. **Read-Only Reentrancy Across Composable Protocols:** During Balancer/Curve/ETH liquidity removal, external `receive()` callbacks fire *before* the pool's internal invariant/virtual price is updated. Any lending protocol reading `pool.get_virtual_price()` during that callback reads an inflated price; check the target pool's reentrancy lock even on `view` functions.
3. **EIP-712 Signature Replay, Cross-Chain `chainid` & `ecrecover` Malleability:** Ensure EIP-712 domain separators recompute dynamically if `block.chainid` changes (hard forks), include a per-user `nonces[signer]++` and `deadline >= block.timestamp`, reject `ecrecover` returning `address(0)`, and use OpenZeppelin's `ECDSA.recover` (enforcing low-`s` malleability).
4. **Fee-on-Transfer, Rebasing & Non-Standard ERC-20 Tokens:** Do not assume `token.transferFrom(user, address(this), amount)` increases the contract's balance by `amount`; measure actual received amount (`balAfter - balBefore`) and use `SafeERC20.safeTransferFrom` (handling USDT's missing boolean return).
5. **Slippage (`minAmountOut` > 0) & Deadline Protection:** Flag any swap or liquidity call that hardcodes `amountOutMin = 0` or `deadline = block.timestamp` (which provides zero MEV/sandwich or mempool delay protection).

## 4. Vulnerable vs. Hardened Pattern
```solidity
// ❌ VULNERABLE: Hardcodes amountOutMin = 0 & deadline = block.timestamp (100% sandwichable)
router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);

// ✅ HARDENED: Caller-specified slippage floor & expiration deadline
function swapWithSlippage(uint256 amountIn, uint256 minAmountOut, uint256 deadline) external {
    require(minAmountOut > 0, "Zero slippage protection");
    require(block.timestamp <= deadline, "Expired deadline");
    router.swapExactTokensForTokens(amountIn, minAmountOut, path, msg.sender, deadline);
}
```
