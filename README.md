# ethexposed

> On-chain attack detector for Ethereum wallets — client-side, zero backend, full history from block 0.

Paste any Ethereum address and find out if it has been targeted by dust attacks, address poisoning, malicious token approvals, or fake airdrops. No signup, no wallet connection, no browser extension, no data stored anywhere.

**This is not an AML or compliance tool.** It analyzes wallets from the perspective of the owner — telling you whether you have been attacked, not whether you are suspicious.

---

## Table of contents

- [What it detects](#what-it-detects)
- [Architecture](#architecture)
- [Detection logic](#detection-logic)
  - [Dust attack](#1-dust-attack)
  - [Address poisoning](#2-address-poisoning)
  - [Token approvals](#3-token-approvals)
  - [Suspicious token scoring](#4-suspicious-token-scoring)
- [Data sources](#data-sources)
- [Setup](#setup)
- [Deployment](#deployment)
- [API rate limits](#api-rate-limits)
- [Privacy model](#privacy-model)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## What it detects

| Check | Status | Method |
|---|---|---|
| Dust Attack (ETH) | ✅ v0.1 | ETH tx history, USD threshold via live price |
| Dust Attack (ERC-20) | ✅ v0.1 | Token transfer history, stablecoin USD value |
| Address Poisoning | ✅ v0.1 | Dual prefix/suffix heuristic against victim + contacts |
| Unlimited Approvals | ✅ v0.1 | `eth_getLogs` on `Approval` topic, `MaxUint256` detection |
| Large Approvals | ✅ v0.1 | `eth_getLogs`, threshold > 100k tokens × 1e18 |
| Suspicious Token Airdrop | ✅ v0.1 | Multi-signal scoring: token list + Etherscan + DexScreener |
| NFT Phishing (ERC-721) | 🔜 v0.2 | Unsolicited transfers + off-chain metadata scanning |
| Permit Phishing (ERC-2612) | 🔜 v0.2 | `Permit` event log scanning |
| Sweeper Bot | 🔜 v0.2 | Same-block ETH in → full drain pattern |
| Sandwich Attack (MEV) | 🔜 v0.3 | DEX swap log analysis, price impact comparison |

---

## Architecture

ethexposed is a **single HTML file** with no build system, no package manager, no runtime dependencies, no backend.

```
index.html
├── <style>          — all CSS, inline
├── <body>           — static UI shell
└── <script>         — all application logic, inline
    ├── Config       — API keys, thresholds, RPC endpoint list
    ├── Utilities    — formatting helpers, address parsing
    ├── Data layer   — Etherscan v2, RPC fallback chain, DexScreener, CoinGecko
    ├── Checks       — one async function per attack type
    ├── Renderer     — builds result HTML from check outputs
    └── Main         — scan pipeline orchestration
```

### Scan pipeline (sequential)

```
1.  Validate address format  — /^0x[0-9a-fA-F]{40}$/
2.  Parallel:
      a. ETH tx history      — Etherscan txlist, all pages, startblock=0
      b. Current block       — eth_blockNumber via RPC
3.  ERC-20 token transfers   — Etherscan tokentx, all pages, startblock=0
4.  Parallel:
      a. Known token lists   — Uniswap tokens.uniswap.org + CoinGecko all.json
      b. ETH/USD price       — CoinGecko simple/price
5.  checkDust()              — ETH + ERC-20 micro-transactions
6.  checkPoisoning()         — zero-value txs from vanity lookalike addresses
7.  checkApprovals()         — eth_getLogs in 100k-block chunks, RPC fallback
8.  checkSuspiciousTokens()
      a. fetchVerifiedStatus()       — Etherscan getsourcecode, 5 parallel
      b. fetchDexScreenerLiquidity() — DexScreener tokens/v1, 30 per call
9.  renderResults()          — inject HTML, scroll into view
```

All processing occurs in the user's browser. No data passes through any server operated by this project.

---

## Detection logic

### 1. Dust Attack

**Definition:** Micro-value transactions sent to a wallet to enable chain-analysis clustering — by observing when and where the dust is subsequently moved, an attacker can link multiple addresses belonging to the same user.

#### ETH dust

The threshold is denominated in USD and converted to ETH at scan time:

```javascript
dustThresholdETH = DUST_USD_THRESHOLD / ethPriceUSD
// default: $1.00 / currentPrice
// fallback (CoinGecko unreachable): DUST_ETH_FALLBACK = 0.0004 ETH
```

A transaction is flagged as dust if all of the following hold:

```
tx.to      == victim address           (incoming)
tx.from    != victim address           (not self-transfer)
tx.value    > 0                        (zero-value = poisoning candidate)
tx.value    < dustThresholdETH
tx.from    ∉ victim's outgoing contacts
```

The contact exclusion prevents legitimate small payments from known addresses (e.g., a friend sending a test transaction) from being flagged.

#### ERC-20 token dust

For **stablecoins** (USDT, USDC, DAI, BUSD, TUSD), the token amount directly approximates USD value:

```javascript
isDust = tokenAmount > 0 && tokenAmount < DUST_TOKEN_USD_THRESHOLD  // $1.00
```

For **unknown tokens**, quantity extremes serve as the signal:

```javascript
isDust = (tokenAmount > 0 && tokenAmount < 10)     // micro-quantity
      || (tokenAmount > 1e12)                       // astronomical quantity of worthless token
```

---

### 2. Address Poisoning

**Definition:** An attacker generates a vanity Ethereum address that visually resembles both the victim's own address (same prefix) and a known contact's address (same suffix). They then send zero-value transactions from this fake address, hoping the victim will copy it from their transaction history.

#### Heuristic

The fake address must satisfy **both** constraints simultaneously:

```
fake[0 : PREFIX_LEN] == victim[0 : PREFIX_LEN]     // same prefix as victim
fake[-SUFFIX_LEN : ] == contact[-SUFFIX_LEN : ]    // same suffix as a known contact
```

Default values: `PREFIX_LEN = 6` chars (including `0x`), `SUFFIX_LEN = 4` hex chars.

This dual constraint matches how real poisoning tooling works. Vanity address generators (Profanity2, VanityETH, etc.) brute-force an address matching both constraints simultaneously. The search space is `16^(PREFIX_CHARS + SUFFIX_CHARS)` — feasible on consumer GPUs for 4+4 characters in minutes.

**Why not a simpler "looks like any contact" check?**

A single-side heuristic (fake address resembles any contact) generates many false positives — legitimate addresses on a large network frequently share short suffixes by chance. The dual check requires matching the victim on one end and the contact on the other, which is statistically rare by accident and diagnostic of intentional vanity address generation.

#### Contact set construction

```
contacts = outgoing ETH destinations (txList where from == victim)
         ∪ real incoming ETH senders (txList where to == victim, value > 0)
         ∪ outgoing token destinations (tokenList where from == victim)
         ∪ real incoming token senders (tokenList where to == victim, value > 0)
```

Only zero-value incoming transactions are checked against this set. A non-zero incoming transaction from a lookalike address is not flagged — it could be a legitimate sender with a coincidentally similar address.

---

### 3. Token Approvals

**Method:** `eth_getLogs` with the standard ERC-20 `Approval` topic and the victim address as `topics[1]` (indexed owner).

**Approval event signature:**
```
Approval(address indexed owner, address indexed spender, uint256 value)
topic[0]: 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925
topic[1]: 0x000000000000000000000000{owner_address}
```

**Scan range:** `max(0, currentBlock - 2_000_000)` to `latest`, in chunks of 100,000 blocks.

**RPC resilience:** If a chunk returns an error (most public free RPCs limit `eth_getLogs` block range), the chunk is recursively split in half and retried:

```javascript
async function fetchChunk(from, to) {
  try {
    return await rpc('eth_getLogs', [{ fromBlock, toBlock, topics }]);
  } catch {
    const mid = Math.floor((from + to) / 2);
    return [...await fetchChunk(from, mid), ...await fetchChunk(mid+1, to)];
  }
}
```

**Deduplication:** For each `(tokenContract, spenderContract)` pair, only the log with the highest block number is retained. A user who granted unlimited approval and then revoked it (amount = 0) shows as revoked. Only current state is reported.

**Classification:**
```javascript
MaxUint256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
amount === MaxUint256n          → 'unlimited'   // Critical
amount >  100_000n * 10n**18n  → 'large'        // Warning
amount === 0n                  → ignored        // revoked
```

---

### 4. Suspicious Token Scoring

**Problem with naive approaches:**

- **Token list membership only:** legitimate derivative tokens (USDT.e, stETH, cbETH, USDT Wormhole) are not in base lists and would be false-positively flagged
- **Name pattern matching only:** a carefully named fake token with plausible branding passes; a legitimate new token with an unusual name fails
- **Either approach alone** cannot distinguish a legitimate DeFi token from a honeypot or scam airdrop

**Solution:** Multi-signal scoring.

Each token received by the wallet that is **not** in the Uniswap or CoinGecko token list is scored:

| Signal | Points | API | Rationale |
|---|---|---|---|
| Not in any token list | +25 | Uniswap, CoinGecko | Baseline prior — unknown token |
| Contract not verified on Etherscan | +40 | `getsourcecode` | Unverified = no public source, no ABI, no audit |
| Name/symbol mimics a known project | +20 | Local pattern match | Indicates impersonation intent |
| DEX liquidity < $1,000 USD | +15 | DexScreener `tokens/v1` | Worthless or honeypot — no real market |

```
score ≥ 70  →  Critical   (almost certainly an attack)
score 40–69 →  Warning    (suspicious, verify before interacting)
score < 40  →  Not reported
```

**Example outcomes:**

| Token | Not in list | Unverified | Mimics brand | Low liquidity | Score | Result |
|---|---|---|---|---|---|---|
| USDT Wormhole | ✅ in list | — | — | — | 0 | Not reported ✓ |
| Random new DeFi token | +25 | verified (+0) | no (+0) | $500k liq (+0) | 25 | Not reported ✓ |
| "UniswapReward" unverified $0 liq | +25 | +40 | +20 | +15 | **100** | Critical ✓ |
| Unknown token, verified, $0 liq | +25 | +0 | +0 | +15 | 40 | Warning ✓ |

**API batching:**
- `getsourcecode`: 5 contracts queried in parallel per batch to stay within rate limits
- DexScreener: up to 30 contract addresses per API call (API limit), one call per batch

---

## Data sources

| Service | Endpoint | Auth | Rate limit | Used for |
|---|---|---|---|---|
| Etherscan API v2 | `api.etherscan.io/v2/api` | Free API key | 5 req/s · 100k/day | tx history, token transfers, contract verification |
| CoinGecko | `api.coingecko.com/api/v3/simple/price` | None | ~30 req/min | ETH/USD price |
| Uniswap Token List | `tokens.uniswap.org` | None | Unrestricted | Token whitelist |
| CoinGecko Token List | `tokens.coingecko.com/uniswap/all.json` | None | Unrestricted | Extended token whitelist |
| DexScreener | `api.dexscreener.com/tokens/v1/ethereum/{...}` | None | 300 req/min | DEX liquidity for token scoring |
| Ankr | `rpc.ankr.com/eth` | None | ~30 req/s public | `eth_getLogs`, `eth_blockNumber` |
| PublicNode | `ethereum.publicnode.com` | None | Moderate | RPC fallback #2 |
| LlamaRPC | `eth.llamarpc.com` | None | Moderate | RPC fallback #3 |

RPC endpoints are tried in order — on any error the next endpoint is attempted automatically.

---

## Setup

### 1. Get a free Etherscan API key

Register at [etherscan.io/register](https://etherscan.io/register) — no credit card required.
Go to **My Account → API Keys → Add**. The free tier covers 5 req/s and 100,000 calls/day.

### 2. Insert the key

Open `index.html` and find the configuration block at the top of the `<script>` tag:

```javascript
// ─────────────────────────────────────────────
//  ★  INSERT YOUR ETHERSCAN API KEY HERE
//     Free registration: etherscan.io/register
// ─────────────────────────────────────────────
const ETHERSCAN_KEY = 'YourApiKeyToken';
```

Replace `YourApiKeyToken` with your key. This is the only required change.

### 3. Run locally

```bash
# No build step required.

# Option A — open directly
open index.html

# Option B — VS Code Live Server
# Install "Live Server" by Ritwick Dey → right-click → Open with Live Server

# Option C — Python
python3 -m http.server 8080
# → http://localhost:8080
```

### 4. Tunable constants

```javascript
const DUST_USD_THRESHOLD       = 1.0;    // ETH dust threshold in USD
const DUST_ETH_FALLBACK        = 0.0004; // used if CoinGecko unreachable
const DUST_TOKEN_USD_THRESHOLD = 1.0;    // stablecoin dust threshold in USD
const POISON_PREFIX_CHARS      = 4;      // hex chars matched against victim prefix
const POISON_SUFFIX_CHARS      = 4;      // hex chars matched against contact suffix
const LARGE_APPROVAL           = BigInt('100000000000000000000000'); // 100k × 1e18
```

---

## Deployment

### Privacy-preserving (recommended)

1. **Domain** — [Njalla](https://njal.la), pay with Monero. Domain registered in Njalla's name, not yours.
2. **Hosting** — Njalla static hosting, [PrivateWeb](https://privateweb.is) (Switzerland), or [Orangewebsite](https://www.orangewebsite.com) (Iceland). Pay with XMR.
3. **Upload** — connect via SFTP from a VPN or Tor exit node. Never upload from your real IP.
4. **Fonts** — remove the Google Fonts `<link>` tag before deploying (see below).

#### Remove Google Fonts

The `<link>` tag in `<head>` causes each visitor's browser to contact Google's CDN, exposing their IP:

```html
<!-- Remove this -->
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono...">
```

Replace the CSS font variables with system equivalents:

```css
--mono: 'Courier New', Courier, monospace;
--dis:  Impact, 'Arial Narrow', sans-serif;
--sans: system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
```

Or self-host the font files: download WOFF2 from [google-webfonts-helper.herokuapp.com](https://google-webfonts-helper.herokuapp.com), place alongside `index.html`, and use `@font-face` declarations.

### GitHub Pages (non-anonymous)

1. Push `index.html`, `README.md`, `LICENSE` to a public repository
2. **Settings → Pages → Source → main**
3. Live at `https://username.github.io/ethexposed`

⚠️ Do not commit your Etherscan API key to a public repository.

---

## API rate limits

Approximate API calls per scan for an active wallet with ~500 transactions:

| Call | Count |
|---|---|
| Etherscan `txlist` | 1–5 pages |
| Etherscan `tokentx` | 1–5 pages |
| Etherscan `getsourcecode` | 1 per unique unknown token (batched 5×) |
| CoinGecko price | 1 |
| Uniswap token list | 1 (cached) |
| CoinGecko token list | 1 (cached) |
| DexScreener | 1 per 30 unknown token contracts |
| RPC `eth_blockNumber` | 1 |
| RPC `eth_getLogs` | 20–40 chunks |

The Etherscan free tier (100k calls/day) supports approximately **3,000–5,000 scans/day**. RPC and DexScreener calls are unrestricted.

---

## Privacy model

### Data transmitted per scan

| Data | Recipient | Purpose |
|---|---|---|
| Ethereum address | Etherscan API | Transaction and token transfer history |
| Ethereum address | Public RPC nodes | `eth_getLogs` for approvals |
| Token contract addresses | Etherscan API | Contract source verification |
| Token contract addresses | DexScreener | Liquidity lookup |
| (none — no user data) | CoinGecko | ETH price and token list |

### Data not transmitted

- Raw transaction data (processed locally after fetch)
- Check results and scores
- Browser fingerprint or user agent (beyond standard HTTP headers sent by the browser itself)

### Etherscan API key

The key is embedded in the HTML source and visible to anyone who views the page source. On the free tier, the key is rate-limited (100k calls/day). If abused, regenerate it in the Etherscan dashboard and redeploy the file — no downtime beyond the file update.

For self-hosters who want to prevent key scraping: the key cannot be meaningfully hidden in a client-side-only architecture without a proxy server. If key abuse is a concern, set up a minimal serverless function (Cloudflare Worker, Vercel Edge Function) that proxies Etherscan requests without exposing the key.

---

## Known limitations

**Approval scan depth**
`eth_getLogs` on public RPCs scans the last ~2M blocks (~1 year). Wallets older than 1 year may have historical unlimited approvals outside this window that are not detected. Increasing the scan range requires a paid RPC endpoint with higher `eth_getLogs` limits.

**Dust threshold precision**
The USD threshold uses a single CoinGecko price fetch at scan time. Intraday ETH volatility may cause borderline transactions to be misclassified. The `DUST_ETH_FALLBACK` is used when CoinGecko is unreachable.

**Token list freshness**
Token lists are fetched fresh per scan but represent a point-in-time snapshot. New legitimate tokens not yet in the Uniswap or CoinGecko lists will appear as unknown. The scoring system partially compensates — a legitimate new token typically has a verified contract and real liquidity, keeping its score below the warning threshold.

**Poisoning false negatives**
Attackers using more than `POISON_PREFIX_CHARS + POISON_SUFFIX_CHARS` matching characters, or matching different character positions, will not be detected at default settings. Increasing the prefix/suffix constants reduces false negatives at the cost of more false positives.

**ERC-777 and non-standard approval mechanisms**
The approval check is specific to the ERC-20 `Approval` event. ERC-777 uses `AuthorizedOperator` and is not currently detected.

**No current approval state verification**
The tool reports the most recent approval log per `(token, spender)` pair. If the spender contract has since been self-destructed or upgraded, the reported approval may no longer be exploitable. Verifying current allowance state would require additional `eth_call` queries for each approval.

---

## Roadmap

### v0.2
- [ ] **Permit phishing** — scan `Permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` events (ERC-2612). These off-chain signatures grant allowances with no visible on-chain approval transaction, making them invisible to the current approval scanner.
- [ ] **Sweeper bot** — detect: ETH arrives → full balance drained to unknown address within same or next block. Indicates compromised private key with automated mempool watcher.
- [ ] **NFT phishing** — detect unsolicited ERC-721/ERC-1155 transfers. Requires off-chain `tokenURI` fetching to check for phishing URLs in metadata.

### v0.3
- [ ] **Sandwich attack** — compare executed DEX swap price against reconstructed expected price from block-level pool state. Requires parsing Uniswap V2/V3 `Swap` events.
- [ ] **TRON support** — TronScan API, similar attack surface (high USDT volume makes TRX wallets frequent targets).
- [ ] **Shareable results** — URL-encoded result summary, no backend required.
- [ ] **Self-hosted fonts** — remove Google Fonts CDN dependency.

### v0.4+
- [ ] **Honeypot detection** — check outgoing transfer history of received tokens. Zero sells from other wallets = honeypot candidate.
- [ ] **Malicious contract interaction** — flag transactions where `input` contains an unrecognized function selector called on an unverified contract.
- [ ] **ENS linkability** — detect registered ENS names on the wallet, which publicly tie it to an on-chain identity.

---

## Contributing

**High-value contributions:**

- **False negative reports** — wallet address + attack type + relevant tx hashes. Direct impact on detection accuracy.
- **False positive reports** — token address + reason it is legitimate. Helps calibrate scoring thresholds.
- **New heuristics** — issue describing the attack pattern, relevant EVM events, example wallet addresses. Code PRs welcome but an issue is enough.
- **RPC endpoint additions** — public endpoints with better `eth_getLogs` support than the current fallback chain.

**Out of scope:**
- UI changes without functional improvement
- External dependency additions (zero-dependency architecture is intentional)
- Backend infrastructure proposals (client-side is a core design constraint, not a limitation)

---

## License

MIT. See [LICENSE](LICENSE).

---

## Acknowledgements

Detection heuristics informed by:

- [Tutela](https://arxiv.org/abs/2201.06811) — Ethereum anonymity heuristics (Béres et al., 2022)
- [eth-labels](https://github.com/dawsbot/eth-labels) — open Ethereum address label dataset
- [revoke.cash](https://revoke.cash) — approval management reference implementation
- Public post-mortems of address poisoning incidents documented on Etherscan and various DeFi security research blogs
