# 🎯 MEV Detector

> Real-time Ethereum MEV (Maximal Extractable Value) detector — identifies sandwich attacks, arbitrage transactions, and frontrunning via Telegram bot.

![Python](https://img.shields.io/badge/Python-3.12+-blue?style=flat-square&logo=python)
![Web3](https://img.shields.io/badge/Web3.py-6.x-orange?style=flat-square)
![Telegram](https://img.shields.io/badge/Telegram-Bot-26A5E4?style=flat-square&logo=telegram)
![Ethereum](https://img.shields.io/badge/Ethereum-Mainnet-627EEA?style=flat-square&logo=ethereum)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 🔍 What is MEV?

**Maximal Extractable Value (MEV)** refers to the profit that can be extracted from reordering, inserting, or censoring transactions within a block. Common MEV strategies include:

- 🥪 **Sandwich Attacks** — front-run and back-run a victim's DEX trade to profit from price impact
- 💱 **Arbitrage** — exploit price differences across DEXes in a single block
- 🏃 **Frontrunning** — copy a profitable transaction with higher gas to execute first

---

## ✨ Features

- 🥪 **Sandwich Attack Detection** — identify attacker, victim TXs, and DEX used
- 💱 **Arbitrage Detection** — track known MEV bots and high gas premium TXs
- 🏃 **Frontrunning Detection** — detect gas premium patterns between sequential DEX TXs
- 🤖 **Known MEV Bot Database** — pre-loaded with known MEV bot addresses
- 📡 **Auto Block Monitor** — continuously scan every new Ethereum block
- 🔔 **Telegram Alerts** — real-time notifications for every MEV event detected

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install web3 requests
```

### 2. Set environment variables

```powershell
# Windows PowerShell
$env:ETHERSCAN_API_KEY = "your_etherscan_api_key"
$env:INFURA_URL        = "https://mainnet.infura.io/v3/your_infura_key"
$env:TELEGRAM_TOKEN    = "your_telegram_bot_token"
$env:TELEGRAM_CHAT_ID  = "your_chat_id"
```

```bash
# Linux / Mac
export ETHERSCAN_API_KEY="your_etherscan_api_key"
export INFURA_URL="https://mainnet.infura.io/v3/your_infura_key"
export TELEGRAM_TOKEN="your_telegram_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
```

### 3. Run as Telegram Bot

```bash
python mev_detector.py
```

### 4. Quick Scan (one-time)

```bash
python mev_detector.py scan 25140000
```

---

## 🤖 Telegram Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome & instructions |
| `/scan [block]` | Scan specific block for MEV |
| `/latest` | Scan latest block |
| `/monitor on/off` | Toggle auto block monitoring |
| `/status` | Current block & gas price |
| `/bots` | List known MEV bot addresses |
| `/help` | Show all commands |

### Example

```
/scan 25140000
/latest
/monitor on
/bots
```

---

## 📊 Sample Output

```
🎯 MEV DETECTED — Block #25140000
━━━━━━━━━━━━━━━━━━━━━━
📦 Total TXs   : 234
🔄 DEX TXs     : 18
⚡ MEV Found   : 3

🥪 Sandwiches  : 1
💱 Arbitrages  : 2
🔴 High Risk   : 2

🔴 SANDWICH ATTACK
👤 Attacker: 0xae2fc483...
🏊 DEX: Uniswap V2
🎯 Victims: 1
⚠️ Known Bot: Jaredfromsubway.eth

🔴 ARBITRAGE — MEV Bot (Generalized)
🤖 Bot: 0x00000000...
🏊 DEX: Uniswap V3
🔧 Fn: exactInputSingle (V3)
```

---

## 🏗️ Architecture

```
mev_detector.py
├── Web3Client          → Web3.py RPC (block & TX data)
├── EtherscanClient     → Etherscan V2 API (internal TXs)
├── MEVAnalyzer         → Core detection engine
│   ├── detect_sandwich()   → sandwich attack detection
│   ├── detect_arbitrage()  → arbitrage detection
│   ├── detect_frontrun()   → frontrunning detection
│   └── scan_block()        → full block MEV scan
├── MEVReporter         → Format & send Telegram alerts
└── MEVBot              → Telegram bot with commands
```

---

## 🎯 Detection Logic

### Sandwich Attack
```
Pattern: [buy TX] → [victim TX] → [sell TX]
- Same attacker address
- Same DEX router
- Victim TX sandwiched between attacker's buy/sell
- Window: 3 transactions
```

### Arbitrage
```
Pattern: Known MEV bot + DEX interaction
- Address matches known MEV bot database
- High gas premium (>3x average)
```

### Frontrunning
```
Pattern: High gas TX before similar TX
- Same DEX router & function
- Gas premium > 1.5x next TX
- Different sender addresses
```

---

## 🤖 Known MEV Bots

| Address | Label |
|---------|-------|
| `0x00000000003b...` | MEV Bot (Generalized) |
| `0x00000000003...` | MEV Bot (Sandwich) |
| `0xae2fc483...` | Jaredfromsubway.eth |
| `0x6b75d8af...` | MEV Bot (Arbitrage) |

---

## 🔧 API Keys

| Service | Get Key | Free Tier |
|---------|---------|-----------|
| Infura | [infura.io](https://infura.io) | 100K req/day |
| Etherscan | [etherscan.io/apis](https://etherscan.io/apis) | 5 req/sec |
| Telegram Bot | [@BotFather](https://t.me/BotFather) | Free |

---

## 👤 Author

**Rizal** — [@rizalcodes](https://github.com/rizalcodes)

> Building Web3 tools with Python 🐍⛓️

---

## 📄 License

MIT License — free to use, modify, and distribute.
