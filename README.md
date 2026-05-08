# ethexposed

> On-chain attack detector for Ethereum wallets — client-side, zero backend, full history from block 0.

Paste any Ethereum address and instantly find out if it has been targeted by dust attacks, address poisoning, malicious token approvals, or fake airdrops. No signup, no wallet connection, no browser extension, no data stored anywhere.

**This is not an AML or compliance tool.** It analyzes wallets from the perspective of the owner — telling you whether you have been attacked, not whether you are suspicious.

🔗 **[Try it live →](https://ethexposed.xyz)**

---

## What it detects

| Check | Status |
|---|---|
| Dust Attack (ETH + ERC-20) | ✅ Live |
| Address Poisoning | ✅ Live |
| Unlimited / Large Token Approvals | ✅ Live |
| Suspicious Token Airdrop | ✅ Live |
| NFT Phishing | 🔜 v0.2 |
| Permit Phishing (ERC-2612) | 🔜 v0.2 |
| Sweeper Bot | 🔜 v0.2 |
| Sandwich Attack (MEV) | 🔜 v0.3 |

---

## How it works

Everything runs **client-side in your browser**. No backend, no database, no server owned by this project.

When you scan an address:

1. Full ETH transaction history is fetched from **block 0** via Etherscan API v2
2. Full ERC-20 token transfer history is fetched from block 0
3. Known token lists are loaded from Uniswap and CoinGecko
4. All checks run locally in JavaScript — nothing is stored or sent to any third party beyond Etherscan's public API and public Ethereum RPC nodes (the same services any block explorer uses)
5. For unrecognized tokens, contract verification (Etherscan) and DEX liquidity (DexScreener) are queried to compute a suspicion score

---

## Detection logic

### Dust attack

The threshold is denominated in **USD**, not ETH — converted at scan time using the live CoinGecko price. This prevents false negatives caused by ETH price appreciation. A transaction is flagged if:

- It is an incoming ETH or token transfer with value > 0
- Value is below the dust threshold ($1.00 default)
- The sender has never received funds from this wallet (unknown contact)

For ERC-20 tokens, stablecoin amounts are used directly as USD value. For unknown tokens, micro-quantities and astronomical quantities are both flagged as dust signals.

### Address poisoning

The heuristic requires the fake address to satisfy **both** constraints simultaneously:

```
fake_address[0 : N] == victim_address[0 : N]     // same prefix as victim
fake_address[-N : ] == contact_address[-N : ]    // same suffix as a known contact
```

This mirrors how real poisoning tools work. Vanity address generators brute-force an address matching both constraints — the attacker crafts something that looks like the victim from the left and the intended recipient from the right, designed to exploit copy-paste behavior in transaction history.

A naive "similar to any contact" check is not sufficient — it produces too many false positives. The dual constraint is diagnostic of intentional vanity address generation.

### Token approvals

`eth_getLogs` with the ERC-20 `Approval` topic, scanned in 100k-block chunks across the last ~2 million blocks. For each `(token, spender)` pair, only the most recent log is kept — correctly handles revoked approvals. Unlimited = `MaxUint256`. Large = > 100k tokens × 1e18.

### Suspicious token scoring

Each unrecognized token received by the wallet is scored (0–100):

| Signal | Points | Source |
|---|---|---|
| Not in any known token list | +25 | Uniswap + CoinGecko |
| Contract not verified on Etherscan | +40 | `getsourcecode` |
| Name/symbol mimics a known project | +20 | Pattern matching |
| DEX liquidity < $1,000 | +15 | DexScreener |

```
≥ 70  →  Critical
40–69 →  Warning
< 40  →  Not reported
```

This prevents false positives on legitimate derivative tokens (USDT Wormhole, stETH, cbETH) while reliably catching unverified zero-liquidity scam airdrops.

---

## Architecture

A single `index.html` file — no build system, no npm, no runtime dependencies, no backend.

```
index.html
├── <style>     — all CSS inline
├── <body>      — static UI shell
└── <script>    — all application logic inline
    ├── Config       — thresholds, RPC list
    ├── Data layer   — Etherscan v2, RPC fallback chain, DexScreener, CoinGecko
    ├── Checks       — one function per attack type
    ├── Renderer     — builds result HTML from check outputs
    └── Main         — scan pipeline orchestration
```

---

## Data sources

| Service | Purpose | Key required |
|---|---|---|
| Etherscan API v2 | tx history, token transfers, contract verification | ✅ Free |
| CoinGecko | ETH/USD price, token list | ❌ No |
| Uniswap Token List | Known token whitelist | ❌ No |
| DexScreener | DEX liquidity for token scoring | ❌ No |
| Ankr / PublicNode / LlamaRPC | Ethereum RPC (approval log scanning) | ❌ No |

---

## Self-hosting

The tool is a single static HTML file. To run your own instance:

1. Get a free Etherscan API key at [etherscan.io/register](https://etherscan.io/register)
2. Open `index.html`, find `const ETHERSCAN_KEY = 'YourApiKeyToken'` and replace with your key
3. Upload to any static hosting — no server required

---

## Privacy

- No analytics, no tracking, no cookies
- No data is sent to any server operated by this project
- Your address is sent only to Etherscan's API and public Ethereum RPC nodes — the same services used by etherscan.io itself
- The Etherscan API key is embedded in the HTML source and visible to anyone viewing the page source — on the free tier this is rate-limited and can be regenerated at any time

---

## Known limitations

- **Approval scan depth** — scans the last ~2M blocks (~1 year). Older approvals may not be detected on free public RPCs.
- **Token list freshness** — new legitimate tokens not yet in Uniswap/CoinGecko lists appear as unknown. The scoring system compensates: a real token typically has a verified contract and real liquidity, keeping its score below the warning threshold.
- **ERC-777** — uses a different approval mechanism (`AuthorizedOperator`) not currently detected.

---

## Roadmap

- [ ] v0.2 — Permit phishing (ERC-2612 `Permit` event scanning)
- [ ] v0.2 — Sweeper bot detection (same-block ETH in → full drain)
- [ ] v0.2 — NFT phishing (unsolicited ERC-721 + metadata URL scanning)
- [ ] v0.3 — Sandwich attack detection (MEV, DEX swap price impact)
- [ ] v0.3 — TRON network support
- [ ] v0.3 — Shareable result links (URL-encoded, no backend)
- [ ] v0.4 — Honeypot detection (zero outgoing transfers from other wallets)

---

## Contributing

PRs welcome. The highest-value contributions are:

- **False negative reports** — a wallet that was attacked but not detected. Open an issue with the address, attack type, and relevant transaction hashes.
- **False positive reports** — something flagged that is clearly legitimate. Include the token address and why you believe it is safe.
- **New heuristics** — describe the attack pattern, relevant EVM events, and example wallet addresses. A well-written issue is enough; code PR optional.

Please keep the zero-dependency, single-file architecture. No build systems, no npm packages, no backend proposals.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

Heuristics informed by:
- [Tutela](https://arxiv.org/abs/2201.06811) — Ethereum anonymity heuristics research (Béres et al., 2022)
- [eth-labels](https://github.com/dawsbot/eth-labels) — open Ethereum address label dataset
- [revoke.cash](https://revoke.cash) — token approval management reference
