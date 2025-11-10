# Revised Risk Assessment - Assuming Trusted TSS

**Date**: 2025-11-10  
**Assumption**: TSS is properly implemented with threshold signatures and can be trusted  
**Impact**: Significantly reduces severity of TSS-related vulnerabilities

---

## Threat Model Revision

### **Original Threat Actors**
1. ❌ ~~Malicious TSS (WithdrawCap holder)~~ → **NOW TRUSTED**
2. ✅ Compromised Admin (AdminCap holder) → **STILL THREAT**
3. ✅ Malicious/Careless Users → **STILL THREAT**
4. ✅ External Attackers (no capabilities) → **STILL THREAT**

### **Trust Boundaries (Revised)**

```
┌─────────────────────────────────────────────────────────┐
│                   TRUSTED ZONE                          │
│                                                         │
│  ┌──────────────────────────────────────┐              │
│  │  TSS (WithdrawCap holder)            │              │
│  │  - Threshold signatures required     │              │
│  │  - Independent validators            │              │
│  │  - Follows protocol correctly        │              │
│  │  - Won't abuse gas_budget           │              │
│  │  - Won't drain vaults maliciously   │              │
│  └──────────────────────────────────────┘              │
│                                                         │
└─────────────────────────────────────────────────────────┘
                         │
                         │ Interacts with
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   UNTRUSTED ZONE                        │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │    Admin     │  │    Users     │  │  Attackers   │ │
│  │  (AdminCap)  │  │  (depositors)│  │   (none)     │ │
│  │              │  │              │  │              │ │
│  │ Can abuse:   │  │ Can cause:   │  │ Limited to:  │ │
│  │ - Nonce      │  │ - User errors│  │ - DoS        │ │
│  │ - Pause      │  │ - Spam       │  │ - Front-run  │ │
│  │ - Whitelist  │  │              │  │              │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Re-Evaluated Vulnerabilities

### ⚠️ **CRITICAL Severity (Remain Critical)**

#### ✅ **CVE-002: Admin Nonce Reset Enables Replay Attacks**
**Original Severity**: CRITICAL (CVSS 8.8)  
**Revised Severity**: **CRITICAL (CVSS 8.8)** - UNCHANGED  
**Reason**: This is an **ADMIN** vulnerability, not TSS

**Analysis**:
- Admin can still call `reset_nonce(gateway, old_nonce, admin_cap)`
- TSS trust doesn't protect against admin abuse
- Admin compromise is separate threat vector
- Replay attacks remain possible if admin malicious

**Impact**: UNCHANGED - Admin can enable replay of previous withdrawals
**Priority**: **P0 - MUST FIX**

```move
// Admin can do this regardless of TSS:
reset_nonce(gateway, 100, admin_cap);  // Rewind nonce
// Old TSS withdrawal at nonce=100 can be replayed
// Even trusted TSS can't prevent this admin action
```

---

### 📉 **Downgraded from CRITICAL → LOW**

#### CVE-001: Arbitrary SUI Vault Drainage via Gas Budget
**Original Severity**: CRITICAL (CVSS 9.1)  
**Revised Severity**: **LOW (CVSS 3.5)** - MAJOR DOWNGRADE  
**Reason**: Requires TSS to act maliciously, which we now trust won't happen

**Analysis**:
- Trusted TSS will set reasonable gas_budget (e.g., 0.001-0.01 SUI)
- TSS has no incentive to drain SUI vault
- Attack requires compromising threshold validators
- With trusted TSS, this becomes "defense in depth" not "critical vulnerability"

**Revised Impact**: 
- **Likelihood**: VERY LOW (requires trusted entity to become malicious)
- **Impact**: CRITICAL (if TSS compromised)
- **Risk Score**: LOW (likelihood × impact)

**Revised Priority**: **P2 - Defense in Depth**
- Not blocking for production
- Implement as hardening measure
- Good practice but not urgent

```move
// Trusted TSS will do this:
withdraw_impl(gateway, amount, nonce, 1_000_000, cap, ctx);  // 0.001 SUI ✓

// Trusted TSS WON'T do this:
withdraw_impl(gateway, amount, nonce, 1_000_000_000_000, cap, ctx);  // 1000 SUI ✗
```

#### CVE-003: Zero-Amount Withdrawal Gas Theft
**Original Severity**: CRITICAL (CVSS 8.5)  
**Revised Severity**: **LOW (CVSS 3.2)** - MAJOR DOWNGRADE  
**Reason**: Same as CVE-001 - requires TSS malicious behavior

**Analysis**:
- `increase_nonce` is legitimate function for handling failed outbounds
- Trusted TSS will only call with reasonable gas_budget
- No incentive for TSS to abuse this

**Revised Priority**: **P2 - Can implement with CVE-001 fix**

---

### 📉 **Downgraded from HIGH → LOW**

#### CVE-004: MessageContext Active Validation Missing
**Original Severity**: HIGH (CVSS 7.5)  
**Revised Severity**: **LOW (CVSS 3.8)** - DOWNGRADE  
**Reason**: TSS controls `set_message_context`, trusted not to abuse

**Analysis**:
- TSS calls `set_message_context` before authenticated calls
- Trusted TSS will only set active MessageContext
- If TSS is malicious enough to use wrong MessageContext, bigger problems exist

**Revised Priority**: **P3 - Nice to have, not urgent**

```move
// Trusted TSS will correctly:
1. Call set_message_context(active_context, sender, target)
2. Call user's on_call function
3. Call reset_message_context(active_context)

// Won't abuse old MessageContext objects
```

#### CVE-005: No Withdrawal Rate Limiting or Amount Caps
**Original Severity**: HIGH (CVSS 7.2)  
**Revised Severity**: **LOW (CVSS 3.5)** - DOWNGRADE  
**Reason**: Trusted TSS won't perform rapid/large withdrawals maliciously

**Analysis**:
- Rate limiting protects against compromised TSS
- With trusted TSS, withdrawals follow legitimate user requests
- TSS won't drain vaults rapidly

**Revised Priority**: **P2 - Defense in depth, not critical**

**Note**: Still valuable for:
- Circuit breaker during TSS key rotation
- Detection of TSS compromise
- But not urgent if TSS is trusted

#### CVE-006: Old Capabilities Not Destroyed After Revocation
**Original Severity**: HIGH (CVSS 6.8)  
**Revised Severity**: **LOW (CVSS 2.8)** - DOWNGRADE  
**Reason**: Operational issue, not security threat with trusted TSS

**Analysis**:
- Old capabilities exist but are inactive
- Gateway checks `active_withdraw_cap` ID
- TSS won't try to use old capabilities
- Mainly a memory leak / code cleanliness issue

**Revised Priority**: **P3 - Code quality improvement**

```move
// Old capability exists but:
assert!(gateway.active_withdraw_cap == object::id(cap), EInactiveWithdrawCap);
// This check prevents use of old caps ✓
// Trusted TSS won't attempt to use them anyway
```

---

### ✅ **HIGH Severity (Remain High)** - User Protection

#### CVE-007: EVM Address Checksum Not Verified (EIP-55)
**Original Severity**: HIGH (CVSS 6.5)  
**Revised Severity**: **HIGH (CVSS 6.5)** - UNCHANGED  
**Reason**: Protects **USERS** from typos, unrelated to TSS

**Analysis**:
- Users can make typos in EVM addresses
- Without checksum validation, funds sent to wrong address
- This is user protection, not TSS-related
- Important for user experience and safety

**Priority**: **P1 - Important UX/Safety Feature**

```move
// User typos:
deposit(gateway, coins, "0x1234...WRONG", ctx);  // ✗ Should reject
// Checksum validation catches ~99.99% of typos

// TSS trust doesn't help users who make mistakes
```

---

### 📉 **Downgraded from MEDIUM → LOW**

#### CVE-008: Deposit Payload Not Validated On-Chain
**Original Severity**: MEDIUM (CVSS 5.3)  
**Revised Severity**: **LOW (CVSS 4.0)** - SLIGHT DOWNGRADE  
**Reason**: Off-chain validation by trusted TSS/ZetaChain

**Analysis**:
- Payload is validated off-chain by ZetaChain
- TSS/observers will reject malformed payloads
- On-chain validation is redundant if off-chain trusted
- Still worth basic checks (length, schema)

**Revised Priority**: **P3 - Optional hardening**

#### CVE-011: SUI Vault Insolvency Risk  
**Original Severity**: MEDIUM (CVSS 4.8)  
**Revised Severity**: **LOW (CVSS 3.0)** - DOWNGRADE  
**Reason**: Trusted TSS won't drain SUI vault

**Analysis**:
- TSS sets gas_budget responsibly
- SUI vault depletion unlikely with trusted TSS
- Still good to monitor SUI balance
- Alert when low, not enforce hard limit

**Revised Priority**: **P3 - Monitoring/alerting, not hard enforcement**

```move
// Instead of hard enforcement:
assert!(sui_balance > MIN_BALANCE, ESuiTooLow);  // ✗ Unnecessary

// Use soft monitoring:
if (sui_balance < LOW_THRESHOLD) {
    emit SuiVaultLowEvent { balance };  // ✓ Alert operators
}
```

---

### ✅ **MEDIUM Severity (Remain Medium)** - User Protection

#### CVE-009: No Minimum Deposit Amount Validation
**Original Severity**: MEDIUM (CVSS 4.8)  
**Revised Severity**: **MEDIUM (CVSS 4.8)** - UNCHANGED  
**Reason**: Protects against **USER/ATTACKER** spam, unrelated to TSS

**Analysis**:
- Users or attackers can spam tiny deposits
- Creates event log bloat
- Costs more in destination gas than deposit value
- TSS trust doesn't prevent this attack

**Priority**: **P2 - Spam prevention**

```move
// Attacker (not TSS) can do:
for i in 0..10000 {
    deposit(gateway, coin_of_1_unit, receiver, ctx);  // Spam
}
// Creates 10,000 events, costs nothing, bloats system
```

#### CVE-012: Missing Events for Critical State Changes
**Original Severity**: MEDIUM (CVSS 4.5)  
**Revised Severity**: **MEDIUM (CVSS 4.5)** - UNCHANGED  
**Reason**: Observability for **ADMIN** actions, important for audit

**Analysis**:
- Need to monitor admin actions (pause, nonce reset, capability rotation)
- Independent of TSS trust
- Critical for security monitoring and incident response
- Compliance requirement

**Priority**: **P1 - Important for observability**

---

### ✅ **LOW Severity (Unchanged)**

#### CVE-010: No Rate Limiting (Duplicate of CVE-005)
**Already covered above** - Downgraded to LOW

#### CVE-013: No Minimum Gas Budget Validation
**Original Severity**: LOW (CVSS 3.0)  
**Revised Severity**: **VERY LOW (CVSS 2.0)** - FURTHER DOWNGRADE  
**Reason**: Trusted TSS sets gas_budget correctly

#### CVE-014: Indefinite Deposit Pause Possible
**Original Severity**: LOW (CVSS 2.8)  
**Revised Severity**: **LOW (CVSS 2.8)** - UNCHANGED  
**Reason**: Admin abuse vector, unrelated to TSS

#### CVE-015: Type Name Collision Risk
**Original Severity**: LOW (CVSS 2.5)  
**Revised Severity**: **VERY LOW (CVSS 1.5)** - FURTHER DOWNGRADE  
**Reason**: Theoretical risk, very unlikely

---

## Summary Table: Before vs After

| CVE | Issue | Original | Revised | Change | Reason |
|-----|-------|----------|---------|--------|--------|
| **002** | Nonce Reset Replay | CRITICAL | **CRITICAL** | ⚠️ SAME | Admin threat |
| **001** | Gas Budget Drain | CRITICAL | **LOW** | ✅ -2 | TSS trusted |
| **003** | Zero-Amount Theft | CRITICAL | **LOW** | ✅ -2 | TSS trusted |
| **007** | EVM Checksum | HIGH | **HIGH** | ⚠️ SAME | User protection |
| **004** | MessageContext | HIGH | **LOW** | ✅ -1 | TSS trusted |
| **005** | Rate Limiting | HIGH | **LOW** | ✅ -1 | TSS trusted |
| **006** | Old Caps Exist | HIGH | **LOW** | ✅ -1 | Operational |
| **009** | Min Deposit | MEDIUM | **MEDIUM** | ⚠️ SAME | User spam |
| **012** | Missing Events | MEDIUM | **MEDIUM** | ⚠️ SAME | Admin observability |
| **008** | Payload Validation | MEDIUM | **LOW** | ✅ -1 | Off-chain trusted |
| **011** | SUI Insolvency | MEDIUM | **LOW** | ✅ -1 | TSS trusted |
| **013-015** | Various Low | LOW | **VERY LOW** | ✅ -1 | Minor issues |

---

## Revised Priority Roadmap

### **P0 - MUST FIX Before Production** (1 issue)

#### 🔴 **CVE-002: Restrict Nonce Reset**
**Why P0**: 
- Admin can enable replay attacks
- Completely breaks replay protection
- Independent of TSS trust
- Simple fix

```move
// Fix:
entry fun reset_nonce(gateway: &mut Gateway, nonce: u64, _cap: &AdminCap) {
    assert!(nonce > gateway.nonce, ENonceCannotDecrement);  // ✓ Only forward
    gateway.nonce = nonce;
}

// Or better: Remove function entirely
// Use increase_nonce for recovery instead
```

---

### **P1 - Important UX/Safety** (2 issues)

#### 🟡 **CVE-007: Add EIP-55 Checksum Validation**
**Why P1**:
- Protects users from costly typos
- Standard in Ethereum ecosystem
- Important for user trust
- Moderate implementation effort

#### 🟡 **CVE-012: Emit Events for Admin Actions**
**Why P1**:
- Critical for monitoring admin behavior
- Incident response requirement
- Compliance/audit necessity
- Easy to implement

---

### **P2 - Defense in Depth** (4 issues)

#### 🟢 **CVE-001 + CVE-003: Gas Budget Limits**
**Why P2**:
- TSS trusted, so not urgent
- But good defense in depth practice
- Trivial to implement
- Industry best practice
- Reduces blast radius if TSS ever compromised

**Implementation**:
```move
const MAX_GAS_BUDGET_PER_TX: u64 = 100_000_000; // 0.1 SUI
const MAX_GAS_BUDGET_INCREASE_NONCE: u64 = 10_000_000; // 0.01 SUI

public fun withdraw_impl<T>(..., gas_budget: u64, ...) {
    assert!(gas_budget <= MAX_GAS_BUDGET_PER_TX, EGasBudgetTooHigh);
    // ... rest
}

entry fun increase_nonce(..., gas_budget: u64, ...) {
    assert!(gas_budget <= MAX_GAS_BUDGET_INCREASE_NONCE, EGasBudgetTooHigh);
    // ... rest
}
```

#### 🟢 **CVE-009: Minimum Deposit Amount**
**Why P2**:
- Prevents spam attacks
- Reduces event log bloat
- Good UX (prevents user mistakes)

#### 🟢 **CVE-005: Rate Limiting (Optional)**
**Why P2**:
- Nice to have circuit breaker
- Helps detect anomalies
- Not critical with trusted TSS

---

### **P3 - Code Quality** (4 issues)

- CVE-004: MessageContext validation
- CVE-006: Clean up old capabilities  
- CVE-008: Payload schema validation
- CVE-011: SUI vault monitoring
- CVE-013-015: Minor issues

**Why P3**:
- Code cleanliness
- Technical debt
- Not security-critical with trusted TSS
- Can implement in future upgrade

---

## Revised Deployment Checklist

### **Pre-Production (Required)**
- [x] TSS properly implemented ✓ (given)
- [ ] **CVE-002: Fix nonce reset** (P0)
- [ ] CVE-007: EIP-55 checksum validation (P1)
- [ ] CVE-012: Add admin action events (P1)
- [ ] Monitoring dashboards operational
- [ ] Incident response playbook prepared

### **Post-Production (1-2 months)**
- [ ] CVE-001/003: Gas budget limits (P2)
- [ ] CVE-009: Minimum deposit (P2)
- [ ] CVE-005: Rate limiting (P2 optional)

### **Future Upgrades**
- [ ] Code quality improvements (P3)
- [ ] Additional hardening (P3)

---

## Key Insights

### **What Changed**
1. **TSS-related vulnerabilities downgraded** from CRITICAL/HIGH to LOW
   - Gas budget abuse (CVE-001, CVE-003)
   - Rate limiting (CVE-005)
   - MessageContext (CVE-004)
   - SUI insolvency (CVE-011)

2. **Admin vulnerabilities remain unchanged**
   - Nonce reset (CVE-002) - Still CRITICAL
   - Missing events (CVE-012) - Still MEDIUM

3. **User protection features remain important**
   - EIP-55 checksum (CVE-007) - Still HIGH
   - Minimum deposit (CVE-009) - Still MEDIUM

### **What Didn't Change**
- Admin is still untrusted threat actor
- Users can still make mistakes
- Defense in depth is still valuable
- Monitoring and observability still critical

### **Risk Assessment**
**Original**: 3 CRITICAL + 4 HIGH = **High Risk** (not production ready)  
**Revised**: 1 CRITICAL + 1 HIGH = **Medium Risk** (can deploy with single fix)

### **Recommendation**
✅ **Production Ready IF:**
1. CVE-002 (nonce reset) is fixed
2. Basic monitoring is in place
3. Incident response plan exists

✅ **Ideal Production State:**
1. Fix CVE-002 (P0)
2. Implement CVE-007 & CVE-012 (P1)
3. Add CVE-001/003 gas limits (P2 - defense in depth)

The bridge can launch with just the P0 fix, but implementing P1 items significantly improves user experience and operational security.

---

## Final Verdict

### **With Trusted TSS: PRODUCTION READY** (with 1 critical fix)

**Blocking Issue**: 1 (CVE-002)
**Important Issues**: 2 (CVE-007, CVE-012)
**Defense in Depth**: 4 (CVE-001, CVE-003, CVE-005, CVE-009)
**Code Quality**: 4 (CVE-004, CVE-006, CVE-008, CVE-011)

**Estimated Fix Timeline**:
- P0 Fix: 1-2 days
- P1 Fixes: 1 week
- P2 Fixes: 2 weeks (optional)

**Risk Level**: Medium → Low (after P0 fix)
**Production Readiness**: ✅ Yes (fix nonce reset first)
