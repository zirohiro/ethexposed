# ethexposed

**On-chain attack detector for Ethereum wallets.**

Paste any Ethereum address and find out if you've been targeted by dust attacks, address poisoning, malicious token approvals, or fake airdrops — instantly, from your browser. No signup, no wallet connection, no extensions.

![ethexposed screenshot](screenshot.png)

---

## What it detects

| Check | Status |
|---|---|
| Dust Attack | ✅ Live |
| Address Poisoning | ✅ Live |
| Unlimited / Large Token Approvals | ✅ Live |
| Suspicious Token Airdrop (scored) | ✅ Live |
| NFT Phishing | 🔜 v0.2 |
| Permit Phishing (ERC-2612) | 🔜 v0.2 |
| Sweeper Bot | 🔜 v0.2 |
| Sandwich Attack (MEV) | 🔜 v0.2 |

---

## How it works

Everything runs **client-side in your browser**. No backend, no database, no server.

When you scan an address, the page:

1. Fetches the full transaction history from block 0 via **Etherscan API v2**
2. Fetches all token transfers (ERC-20) from block 0
3. Loads the known token list from **Uniswap** and **CoinGecko**
4. Fetches the current ETH price from **CoinGecko** (for USD-denominated dust threshold)
5. Runs all checks locally in JavaScript
6. For suspicious tokens, queries **Etherscan** (contract verification) and **DexScreener** (liquidity) to produce a suspicion score

Your address is sent only to Etherscan's public API and public Ethereum RPC nodes — the same services any block explorer uses. Nothing is stored anywhere.

---

## Suspicion scoring system

Unrecognized tokens receive a suspicion score (0–100):

| Signal | Points | Source |
|---|---|---|
| Not in any known token list | +25 | Uniswap + CoinGecko |
| Contract not verified on Etherscan | +40 | Etherscan `getsourcecode` |
| Name mimics a known project | +20 | Pattern matching |
| DEX liquidity < $1,000 | +15 | DexScreener API |

- **≥ 70 → Critical**
- **40–69 → Warning**
- **< 40 → ignored**

---

## Address poisoning heuristic

The correct heuristic (not just "similar address") requires the fake address to satisfy both conditions simultaneously:

```
fake.prefix == victim.prefix   (first 4 hex chars)
fake.suffix == contact.suffix  (last 4 hex chars)
```

This mirrors how real poisoning tools work — the attacker crafts an address that visually resembles the victim on one end and the intended recipient on the other, to exploit copy-paste behavior in transaction history.

---

## Setup

### 1. Get a free Etherscan API key

Register at [etherscan.io/register](https://etherscan.io/register) — no credit card needed.  
Go to **My Account → API Keys → Add**.

### 2. Add your key to the code

Open `index.html` and find this line near the top of the `<script>` tag:

```javascript
const ETHERSCAN_KEY = 'YourApiKeyToken';
```

Replace `YourApiKeyToken` with your key.

### 3. Run locally

No build step, no npm, no dependencies. Just open `index.html` in your browser, or use VS Code's Live Server extension.

### 4. Deploy

Upload `index.html` to any static hosting:

- **Cloudflare Pages** — drag & drop, free, HTTPS automatic
- **GitHub Pages** — enable in repo settings → Pages → main branch
- **Netlify** — drag & drop deploy

---

## APIs used

| Service | Purpose | Key required |
|---|---|---|
| Etherscan v2 | Transaction history, token transfers, contract verification | ✅ Free |
| CoinGecko | ETH price (USD), token list | ❌ No |
| Uniswap Token List | Known legitimate tokens | ❌ No |
| DexScreener | DEX liquidity for token scoring | ❌ No |
| Ankr / PublicNode / LlamaRPC | Ethereum RPC for approval logs | ❌ No |

---

## Privacy

- No analytics, no tracking, no cookies
- No data is sent to any server operated by this project
- The Etherscan API key is embedded in the HTML — if you host this publicly, be aware the key is visible in the page source. The free tier allows 100k calls/day which is more than enough for personal use.
- For maximum privacy when using the hosted version, use Tor or a VPN

---

## Roadmap

- [ ] v0.2 — Permit phishing detection (ERC-2612 `Permit` events)
- [ ] v0.2 — Sweeper bot detection (ETH in → full drain in same block)
- [ ] v0.2 — NFT phishing (ERC-721 unsolicited transfers + metadata scanning)
- [ ] v0.3 — Sandwich attack detection (MEV via DEX swap log analysis)
- [ ] v0.3 — TRON network support
- [ ] v0.3 — Share results link (URL-encoded, no backend)

---

## Contributing

PRs welcome. If you find a wallet that should be detected but isn't, open an issue with the address and what type of attack it received — that's the most useful contribution possible.

---

## License

MIT — do whatever you want with it.

---

*ethexposed is not a compliance or AML tool. It analyzes wallets from the perspective of the owner — telling you if you've been attacked, not whether you're suspicious.*
