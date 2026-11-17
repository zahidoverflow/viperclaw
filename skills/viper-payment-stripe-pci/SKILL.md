---
name: viper-payment-stripe-pci
description: Payment Processing, Stripe/PayPal Ledger & Financial Precision Auditor. Reviews server-side price calculation, integer minor-unit math, double-entry ledgers, and PCI scope.
---

# ViperClaw Skill 54: Payment Processing, Ledger & Financial Logic Auditor (`viper-payment-stripe-pci`)

## 1. Standards & Open-Source Reference
- **Standards:** PCI-DSS v4.0, Stripe Security Integration Guide, OWASP Business Logic Security Cheat Sheet.
- **Focus:** Auditing checkout flows, subscription webhooks, wallet/credit balances, currency conversion, and refund logic.

## 2. Rapid Discovery Patterns
- Search for `stripe.checkout.Session.create`, `PaymentIntent.create`, `float(`, `amount`, `price`, `quantity`, `discount`, `refund`.

## 3. Technical Audit Checklist
1. **Server-Side Price & Currency Lookup:** Never accept `unit_amount`, `price`, `currency`, or `discount_percent` from client request parameters; accept only `item_id` and `quantity`, validate `quantity > 0` (blocking negative-quantity credit bugs!), and look up the price from the server database.
2. **Exact Integer Minor-Unit / `Decimal` Arithmetic:** Never use IEEE-754 floating-point (`float` in Python, `number` float math in JS) for money (`0.1 + 0.2 == 0.30000000000000004`). Store and compute all monetary values as integer minor units (cents/satoshis/wei) or fixed-precision `Decimal` with explicit `ROUND_HALF_EVEN` / `ROUND_FLOOR`.
3. **Webhook Event Ordering & State-Machine Finality:** Payment webhooks (`checkout.session.completed`, `payment_intent.succeeded`, `charge.dispute.created`) can arrive out of order or multiple times. Verify `stripe.Webhook.construct_event` signature, check `payment_status == "paid"`, and enforce an atomic `WHERE status = 'PENDING'` state transition.
4. **Refund & Partial-Refund Cap Enforcement:** Ensure total cumulative refunds for an order (`SUM(refunds.amount) + new_refund <= order.captured_amount`) are checked inside a `SELECT ... FOR UPDATE` transaction so concurrent refund requests cannot exceed the original payment.
5. **PCI-DSS Scope Isolation:** Ensure raw PAN (card numbers) and CVV never touch application logs, databases, or backend servers—use client-side tokenization (`Stripe Elements`, `Braintree Hosted Fields`).

## 4. Vulnerable vs. Hardened Pattern
```python
# ❌ VULNERABLE: Uses float math, trusts client price, and lacks negative quantity check
total = float(req.json["price"]) * int(req.json["quantity"])
stripe.PaymentIntent.create(amount=int(total * 100), currency="usd")

# ✅ HARDENED: Positive integer quantity, DB price in integer cents, and idempotency key
qty = int(req.json["quantity"])
if qty <= 0 or qty > 100:
    raise ValueError("Invalid quantity")
product = db.get_product(req.json["product_id"])
amount_cents = product.price_cents * qty
stripe.PaymentIntent.create(
    amount=amount_cents,
    currency=product.currency,
    idempotency_key=f"order:{order.id}",
)
```
