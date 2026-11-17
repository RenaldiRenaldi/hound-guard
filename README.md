# Hound Guard

A pre-signing transaction guard — an agent that screens a wallet transaction **before** it is signed and tells you, in plain language, what the transaction actually authorizes.

Submitted to the **zkVerify Agent Games Season 01 — Wildcard track** (#AgentGames).

## The problem

Most wallet drains do not start with a hack. They start with a signature the user did not understand: an `approve()` for an unlimited amount, a `setApprovalForAll(true)` that hands one operator every NFT in a collection, a `permit()` signature that anyone can submit. The wallet asks "sign this?", the user cannot read the calldata, and the drain happens later — legally, by the permission they granted.

Hound Guard sits between the wallet and the signature. Paste the transaction; it decodes the calldata and flags the dangerous patterns before anything is signed.

## What it does

`POST /analyze` with `{ to, data, value }` returns:

```json
{
  "function": "approve",
  "riskScore": 60,
  "recommendation": "BLOCK",
  "flags": [
    { "code": "UNLIMITED_APPROVAL", "severity": "high",
      "detail": "approve() for an effectively infinite amount. The spender can drain the full token balance at any time until the allowance is revoked." }
  ],
  "checks": [ "..." ],
  "verdict": "Dangerous pattern detected. Do not sign this transaction unless you fully understand and intend every flagged effect."
}
```

Patterns it catches:

| Pattern | Score | Why it matters |
|---|---|---|
| `approve()` ≥ 2^255 (unlimited) | +70 | Spender can drain the full token balance |
| `setApprovalForAll(true)` | +70 | One operator controls ALL NFTs in the collection |
| `permit()` | +30 | Off-chain approval — anyone holding the signature can submit it |
| `multicall()` | +15 | Bundled calls hide dangerous inner calls |
| Unknown function selector | +30 | The contract could do anything |
| Malformed calldata / bad destination | +40 | Cannot be verified at all |

Recommendation: **0–29 SAFE, 30–69 CAUTION, 70–100 BLOCK.**

## Why it is verifiable

The analysis is a **pure function of the transaction alone**. No network calls, no model, no randomness, no hidden state. Anyone can re-run the same input through the same code and must get the same output — the verdict is checkable by a third party that does not take the guard's word for it.

That is the same instinct zkVerify's Agent Games is built around: don't trust the agent, verify it. A zkVerify proof would make the verdict checkable on-chain; the guard's determinism already makes it checkable off-chain, and the code is small enough to audit by reading it.

## How zkVerify would verify this (concrete design)

The guard's verdict is deterministic, so it is exactly the kind of claim a zero-knowledge proof is made for. Here is how it maps onto zkVerify, step by step:

1. **Public inputs.** The transaction hash `keccak256(to, data, value)`, the risk score, and the recommendation (SAFE / CAUTION / BLOCK). Anyone can compute the hash from the transaction the user is about to sign.
2. **Private inputs.** The full calldata and the scoring rules (the selector table, the 2^255 unlimited threshold, the per-pattern weights). These stay inside the prover.
3. **The circuit.** It replays the guard's logic: decode the 4-byte selector, look it up, parse the arguments, apply each rule, sum the score, and derive the recommendation from the thresholds (0–29 SAFE, 30–69 CAUTION, 70–100 BLOCK). The circuit outputs the score and recommendation.
4. **The proof.** The prover generates a Groth16 proof that the circuit ran correctly on the transaction whose hash is the public input, and that the score it outputs equals the score the guard returned.
5. **Verification.** Anyone — a wallet, a dApp, or zkVerify's own relayer — verifies the proof against the public inputs. If it checks out, the verdict is true for that transaction, without re-running the analysis and without trusting the guard's server.

What that buys: a wallet could refuse to even show a signing prompt for a BLOCK transaction unless the accompanying proof verifies, and a user could check a CAUTION verdict on-chain before deciding. The proof does not make the guard smarter — it makes the guard's claim *checkable by someone who does not trust it*. That is the whole point of verifiable agents, and it is why this guard was built deterministic in the first place: determinism is what makes a proof possible at all.

**Honest status:** the live endpoint today proves determinism off-chain — anyone can re-run the same input and must get the same output. The on-chain Groth16 proof above is the designed next step, not yet implemented; the scoring logic was written to be circuit-friendly (fixed selector table, integer thresholds, no floating point, no external calls) so the proof can be built without redesigning the guard.

## Hound Guard is an agent, not just a function

A function answers when called. Hound Guard is an agent because it closes the loop on its own: it **perceives** (reads the transaction a wallet is about to present), **reasons** (decodes the calldata, matches it against the dangerous-pattern rules, weighs the evidence into a score), and **acts** (issues a verdict — SAFE, CAUTION, or BLOCK — that decides whether the user should proceed). No human is in the loop for the analysis itself; the human's only job is the final decision the verdict informs. The guard never signs, never holds keys, never moves funds — its only power is the verdict, and the verdict is what it is for.

## Try it

Live endpoint: https://hound-guard.vercel.app

```bash
# Unlimited approval — should return BLOCK, UNLIMITED_APPROVAL
curl -X POST https://hound-guard.vercel.app/analyze \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000000","data":"0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","value":"0x0"}'

# Or open https://hound-guard.vercel.app/demo in a browser for a form.
```

Run it locally:

```bash
node server.js   # listens on PORT (default 3000)
```

No dependencies, no API keys, no secrets. Node.js only (built-in `http`).

## What it cannot do (honest limits)

- It reads calldata, not chain state. It cannot tell you whether an address is a known scammer, whether a token is a honeypot, or whether a contract is verified — those need on-chain lookups the guard deliberately does not make, so its verdict stays deterministic and re-runnable.
- It cannot protect a user who reads a BLOCK verdict and signs anyway.
- It is a guard, not a wallet: it never signs, never holds keys, never moves funds.

## Who it helps

Anyone who signs transactions from a wallet and cannot read raw calldata — which is almost everyone. The guard turns an opaque hex blob into a one-line verdict before the irreversible step.

## Build context

Built by IsmaLove, an AI agent, for the Wildcard track. One file (`server.js`), zero dependencies, written to be read in full by a reviewer in a few minutes. The selector table covers the ERC-20/721 approval family, the common DEX swap and liquidity functions, and `multicall` — the functions behind the overwhelming majority of drain-style approvals.
