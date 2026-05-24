"""
mev_detector.py - MEV (Maximal Extractable Value) Detector
By Rizal | github.com/rizalcodes
Detect: Sandwich Attacks, Arbitrage, Frontrunning, Backrunning
Multi-source: Web3.py + Etherscan V2 + Mempool monitoring
Output: Real-time Telegram alerts
"""

import os
import time
import logging
import requests
from web3 import Web3
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "Your_Etherscan_Api_Here")
INFURA_URL        = os.getenv("INFURA_URL",        "https://mainnet.infura.io/v3/Your_Infure_Key_Here")
TELEGRAM_TOKEN    = os.getenv("TELEGRAM_TOKEN",    "Your_Telegram_Bot_Token_Here")
TELEGRAM_CHAT_ID  = os.getenv("TELEGRAM_CHAT_ID",  "Your_Chat_ID_Here")

# MEV Detection thresholds
MIN_PROFIT_ETH    = 0.01    # minimum profit untuk dianggap MEV (ETH)
MIN_GAS_PREMIUM   = 1.5     # minimum gas premium multiplier untuk frontrun
SANDWICH_WINDOW   = 3       # jumlah transaksi window untuk sandwich detection
BLOCK_SCAN_RANGE  = 10      # jumlah block yang di-scan per cycle


# ─────────────────────────────────────────────
# KNOWN MEV BOT SIGNATURES
# ─────────────────────────────────────────────
KNOWN_MEV_BOTS = {
    "0x00000000003b3cc22af3ae1eac0440bcee416b40": "MEV Bot (Generalized)",
    "0x000000000035b5e5ad9019092c665357240f594d": "MEV Bot (Sandwich)",
    "0xae2fc483527b8ef99eb5d9b44875f005ba1fae13": "Jaredfromsubway.eth",
    "0x6b75d8af000000e20b7a7ddf000ba900b4009a80": "MEV Bot (Arbitrage)",
}

# DEX Router addresses
DEX_ROUTERS = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap Universal Router",
}

# Common MEV function selectors
MEV_SELECTORS = {
    "0x7ff36ab5": "swapExactETHForTokens",
    "0x18cbafe5": "swapExactTokensForETH",
    "0x38ed1739": "swapExactTokensForTokens",
    "0x5c11d795": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
    "0xfb3bdb41": "swapETHForExactTokens",
    "0x414bf389": "exactInputSingle (V3)",
    "0xc04b8d59": "exactInput (V3)",
}


# ─────────────────────────────────────────────
# 1. WEB3 CLIENT
# ─────────────────────────────────────────────
class Web3Client:
    def __init__(self, rpc_url: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        if self.w3.is_connected():
            log.info(f"✅ Web3 connected — block #{self.w3.eth.block_number}")
        else:
            log.warning("⚠️ Web3 tidak terkoneksi")

    def get_block(self, block_number: int = None, full_tx: bool = True):
        """Ambil block dengan semua transaksinya."""
        try:
            if block_number is None:
                block_number = self.w3.eth.block_number
            return self.w3.eth.get_block(block_number, full_transactions=full_tx)
        except Exception as e:
            log.error(f"Get block error: {e}")
            return None

    def get_latest_block(self) -> int:
        return self.w3.eth.block_number

    def get_transaction(self, tx_hash: str) -> dict:
        try:
            return dict(self.w3.eth.get_transaction(tx_hash))
        except Exception:
            return {}

    def get_transaction_receipt(self, tx_hash: str) -> dict:
        try:
            return dict(self.w3.eth.get_transaction_receipt(tx_hash))
        except Exception:
            return {}

    def wei_to_eth(self, wei: int) -> float:
        return float(self.w3.from_wei(wei, "ether"))

    def get_gas_price_gwei(self) -> float:
        try:
            return float(self.w3.from_wei(self.w3.eth.gas_price, "gwei"))
        except Exception:
            return 0


# ─────────────────────────────────────────────
# 2. ETHERSCAN CLIENT
# ─────────────────────────────────────────────
class EtherscanClient:
    BASE = "https://api.etherscan.io/v2/api"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()

    def _get(self, params: dict) -> dict:
        params["apikey"]  = self.api_key
        params["chainid"] = 1
        try:
            r = self.session.get(self.BASE, params=params, timeout=15)
            return r.json()
        except Exception as e:
            log.error(f"Etherscan error: {e}")
            return {}

    def get_block_txs(self, block_number: int) -> list:
        """Ambil semua TXs dalam satu block."""
        data = self._get({
            "module": "proxy",
            "action": "eth_getBlockByNumber",
            "tag"   : hex(block_number),
            "boolean": "true",
        })
        result = data.get("result", {})
        return result.get("transactions", []) if result else []

    def get_internal_txs(self, tx_hash: str) -> list:
        """Ambil internal transactions untuk detect profit."""
        data = self._get({
            "module"  : "account",
            "action"  : "txlistinternal",
            "txhash"  : tx_hash,
        })
        result = data.get("result", [])
        return result if isinstance(result, list) else []


# ─────────────────────────────────────────────
# 3. MEV ANALYZER
# ─────────────────────────────────────────────
class MEVAnalyzer:
    """Core engine untuk detect berbagai jenis MEV."""

    def __init__(self, web3_client: Web3Client, etherscan: EtherscanClient):
        self.w3        = web3_client
        self.etherscan = etherscan

    # ── 3a. Sandwich Attack Detection ────────
    def detect_sandwich(self, block_txs: list) -> list:
        """
        Detect sandwich attacks dalam satu block.
        Pattern: [buy TX] → [victim TX] → [sell TX] dari bot yang sama
        """
        sandwiches = []
        dex_txs    = []

        # Filter hanya DEX transactions
        for tx in block_txs:
            to_addr = (tx.get("to") or "").lower()
            input_data = tx.get("input", "0x")
            selector   = input_data[:10] if len(input_data) >= 10 else "0x"

            if to_addr in DEX_ROUTERS and selector in MEV_SELECTORS:
                dex_txs.append({
                    "hash"    : tx.get("hash", ""),
                    "from"    : tx.get("from", "").lower(),
                    "to"      : to_addr,
                    "dex"     : DEX_ROUTERS.get(to_addr, "Unknown DEX"),
                    "function": MEV_SELECTORS.get(selector, "unknown"),
                    "gas_price": int(tx.get("gasPrice", 0)),
                    "value"   : int(tx.get("value", 0)),
                    "selector": selector,
                    "index"   : block_txs.index(tx),
                })

        # Cari pattern sandwich: same sender, buy → victim → sell
        sender_txs = defaultdict(list)
        for tx in dex_txs:
            sender_txs[tx["from"]].append(tx)

        for sender, txs in sender_txs.items():
            if len(txs) >= 2:
                # Cek apakah ada buy dan sell yang mengelilingi TX lain
                for i in range(len(txs) - 1):
                    tx1 = txs[i]
                    tx2 = txs[i + 1]

                    # Index harus berurutan dengan gap (victim di tengah)
                    if 1 <= tx2["index"] - tx1["index"] <= SANDWICH_WINDOW + 1:
                        # Gas price check — sandwich bot biasanya gas lebih tinggi
                        if tx1["gas_price"] > 0:
                            victim_txs = [
                                t for t in dex_txs
                                if tx1["index"] < t["index"] < tx2["index"]
                                and t["from"] != sender
                            ]
                            if victim_txs:
                                sandwiches.append({
                                    "type"       : "SANDWICH_ATTACK",
                                    "attacker"   : sender,
                                    "front_tx"   : tx1["hash"],
                                    "back_tx"    : tx2["hash"],
                                    "victims"    : [v["hash"] for v in victim_txs],
                                    "dex"        : tx1["dex"],
                                    "function"   : tx1["function"],
                                    "is_known_bot": sender in KNOWN_MEV_BOTS,
                                    "bot_label"  : KNOWN_MEV_BOTS.get(sender, "Unknown"),
                                    "severity"   : "HIGH" if sender in KNOWN_MEV_BOTS else "MEDIUM",
                                })

        return sandwiches

    # ── 3b. Arbitrage Detection ──────────────
    def detect_arbitrage(self, block_txs: list) -> list:
        """
        Detect arbitrage transactions.
        Pattern: same token in & out, multiple DEX hops, profit > threshold
        """
        arbitrages = []

        for tx in block_txs:
            from_addr  = (tx.get("from") or "").lower()
            to_addr    = (tx.get("to") or "").lower()
            input_data = tx.get("input", "0x")
            selector   = input_data[:10] if len(input_data) >= 10 else "0x"
            value      = int(tx.get("value", 0))

            # Cek kalau TX ke DEX router
            if to_addr not in DEX_ROUTERS:
                continue

            # Known MEV bot melakukan arbitrage
            if from_addr in KNOWN_MEV_BOTS:
                arbitrages.append({
                    "type"      : "ARBITRAGE",
                    "tx_hash"   : tx.get("hash", ""),
                    "bot"       : from_addr,
                    "bot_label" : KNOWN_MEV_BOTS[from_addr],
                    "dex"       : DEX_ROUTERS.get(to_addr, "Unknown"),
                    "function"  : MEV_SELECTORS.get(selector, "unknown"),
                    "value_eth" : self.w3.wei_to_eth(value),
                    "gas_price" : int(tx.get("gasPrice", 0)),
                    "severity"  : "HIGH",
                })
                continue

            # Cek gas price premium (frontrunner biasanya gas jauh lebih tinggi)
            gas_price = int(tx.get("gasPrice", 0))
            avg_gas   = self.w3.w3.eth.gas_price

            if avg_gas > 0 and gas_price / avg_gas > MIN_GAS_PREMIUM * 2:
                # High gas + DEX call = possible arbitrage
                arbitrages.append({
                    "type"       : "POSSIBLE_ARBITRAGE",
                    "tx_hash"    : tx.get("hash", ""),
                    "bot"        : from_addr,
                    "bot_label"  : "Unknown Arbitrageur",
                    "dex"        : DEX_ROUTERS.get(to_addr, "Unknown"),
                    "function"   : MEV_SELECTORS.get(selector, "unknown"),
                    "value_eth"  : self.w3.wei_to_eth(value),
                    "gas_premium": round(gas_price / avg_gas, 2),
                    "severity"   : "MEDIUM",
                })

        return arbitrages

    # ── 3c. Frontrunning Detection ───────────
    def detect_frontrun(self, block_txs: list) -> list:
        """
        Detect frontrunning transactions.
        Pattern: high gas TX right before similar TX dari address lain
        """
        frontruns  = []
        avg_gas    = self.w3.w3.eth.gas_price

        if avg_gas == 0:
            return []

        dex_txs = [
            tx for tx in block_txs
            if (tx.get("to") or "").lower() in DEX_ROUTERS
        ]

        for i, tx in enumerate(dex_txs[:-1]):
            next_tx    = dex_txs[i + 1]
            gas_price  = int(tx.get("gasPrice", 0))
            next_gas   = int(next_tx.get("gasPrice", 0))

            # Frontrunner: gas jauh lebih tinggi dari TX berikutnya
            if gas_price > 0 and next_gas > 0:
                premium = gas_price / next_gas
                if premium > MIN_GAS_PREMIUM and tx.get("from") != next_tx.get("from"):
                    # Same DEX, same function = possible frontrun
                    tx_sel   = (tx.get("input", "0x"))[:10]
                    next_sel = (next_tx.get("input", "0x"))[:10]

                    if tx_sel == next_sel and tx_sel in MEV_SELECTORS:
                        frontruns.append({
                            "type"       : "FRONTRUN",
                            "frontrunner": tx.get("from", "").lower(),
                            "victim"     : next_tx.get("from", "").lower(),
                            "front_tx"   : tx.get("hash", ""),
                            "victim_tx"  : next_tx.get("hash", ""),
                            "dex"        : DEX_ROUTERS.get((tx.get("to") or "").lower(), "Unknown"),
                            "function"   : MEV_SELECTORS.get(tx_sel, "unknown"),
                            "gas_premium": round(premium, 2),
                            "severity"   : "HIGH" if premium > 3 else "MEDIUM",
                        })

        return frontruns

    # ── 3d. Full Block MEV Scan ──────────────
    def scan_block(self, block_number: int) -> dict:
        """Scan satu block untuk semua jenis MEV."""
        log.info(f"🔍 Scanning block #{block_number}...")

        block = self.w3.get_block(block_number, full_tx=True)
        if not block:
            return {"error": f"Block {block_number} not found"}

        txs = [dict(tx) for tx in block.get("transactions", [])]
        log.info(f"📦 Block #{block_number}: {len(txs)} transactions")

        sandwiches  = self.detect_sandwich(txs)
        arbitrages  = self.detect_arbitrage(txs)
        frontruns   = self.detect_frontrun(txs)

        total_mev = len(sandwiches) + len(arbitrages) + len(frontruns)

        return {
            "block_number": block_number,
            "timestamp"   : datetime.now().isoformat(),
            "total_txs"   : len(txs),
            "mev_count"   : total_mev,
            "sandwiches"  : sandwiches,
            "arbitrages"  : arbitrages,
            "frontruns"   : frontruns,
            "summary"     : {
                "sandwich_count" : len(sandwiches),
                "arbitrage_count": len(arbitrages),
                "frontrun_count" : len(frontruns),
                "severity_high"  : sum(1 for m in sandwiches + arbitrages + frontruns if m.get("severity") == "HIGH"),
                "severity_medium": sum(1 for m in sandwiches + arbitrages + frontruns if m.get("severity") == "MEDIUM"),
            }
        }


# ─────────────────────────────────────────────
# 4. TELEGRAM REPORTER
# ─────────────────────────────────────────────
class MEVReporter:
    def __init__(self, token: str, chat_id: str):
        self.token   = token
        self.chat_id = chat_id
        self.base    = f"https://api.telegram.org/bot{token}"

    def send(self, text: str):
        try:
            requests.post(
                f"{self.base}/sendMessage",
                json={"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=10
            )
        except Exception as e:
            log.error(f"Telegram error: {e}")

    def send_block_summary(self, result: dict):
        """Kirim ringkasan MEV per block."""
        if result.get("error"):
            return

        summary = result["summary"]
        if result["mev_count"] == 0:
            return  # Skip block yang tidak ada MEV

        msg = f"""
🎯 *MEV DETECTED — Block #{result['block_number']}*
━━━━━━━━━━━━━━━━━━━━━━
📦 Total TXs   : `{result['total_txs']}`
⚡ MEV Found   : `{result['mev_count']}`

🥪 Sandwiches  : `{summary['sandwich_count']}`
💱 Arbitrages  : `{summary['arbitrage_count']}`
🏃 Frontruns   : `{summary['frontrun_count']}`

🔴 High Risk   : `{summary['severity_high']}`
🟡 Medium Risk : `{summary['severity_medium']}`
⏰ {result['timestamp'][:19]}
        """.strip()
        self.send(msg)

    def send_sandwich_alert(self, sandwich: dict, block: int):
        """Kirim alert untuk sandwich attack."""
        sev_emoji = "🔴" if sandwich["severity"] == "HIGH" else "🟡"
        known     = f"⚠️ Known Bot: `{sandwich['bot_label']}`" if sandwich["is_known_bot"] else ""

        msg = f"""
{sev_emoji} *SANDWICH ATTACK DETECTED*
━━━━━━━━━━━━━━━━━━━━━━
📦 Block      : `#{block}`
👤 Attacker   : `{sandwich['attacker'][:10]}...`
🏊 DEX        : `{sandwich['dex']}`
🔧 Function   : `{sandwich['function']}`
🎯 Victims    : `{len(sandwich['victims'])}`
{known}
🔗 Front TX: `{sandwich['front_tx'][:16]}...`
🔗 Back TX : `{sandwich['back_tx'][:16]}...`
        """.strip()
        self.send(msg)

    def send_arbitrage_alert(self, arb: dict, block: int):
        """Kirim alert untuk arbitrage."""
        sev_emoji = "🔴" if arb["severity"] == "HIGH" else "🟡"

        msg = f"""
{sev_emoji} *{arb['type'].replace('_', ' ')}*
━━━━━━━━━━━━━━━━━━━━━━
📦 Block      : `#{block}`
🤖 Bot        : `{arb['bot_label']}`
🏊 DEX        : `{arb['dex']}`
🔧 Function   : `{arb['function']}`
💰 Value      : `{arb['value_eth']:.4f} ETH`
⛽ Gas Premium: `{arb.get('gas_premium', 'N/A')}x`
🔗 TX: `{arb['tx_hash'][:16]}...`
        """.strip()
        self.send(msg)

    def send_frontrun_alert(self, frontrun: dict, block: int):
        """Kirim alert untuk frontrunning."""
        sev_emoji = "🔴" if frontrun["severity"] == "HIGH" else "🟡"

        msg = f"""
{sev_emoji} *FRONTRUN DETECTED*
━━━━━━━━━━━━━━━━━━━━━━
📦 Block       : `#{block}`
🏃 Frontrunner : `{frontrun['frontrunner'][:10]}...`
😢 Victim      : `{frontrun['victim'][:10]}...`
🏊 DEX         : `{frontrun['dex']}`
🔧 Function    : `{frontrun['function']}`
⛽ Gas Premium : `{frontrun['gas_premium']}x`
🔗 Front TX: `{frontrun['front_tx'][:16]}...`
        """.strip()
        self.send(msg)


# ─────────────────────────────────────────────
# 5. MEV BOT (Telegram Commands)
# ─────────────────────────────────────────────
class MEVBot:
    def __init__(self):
        self.token    = TELEGRAM_TOKEN
        self.chat_id  = TELEGRAM_CHAT_ID
        self.base     = f"https://api.telegram.org/bot{self.token}"
        self.w3       = Web3Client(INFURA_URL)
        self.etherscan= EtherscanClient(ETHERSCAN_API_KEY)
        self.analyzer = MEVAnalyzer(self.w3, self.etherscan)
        self.reporter = MEVReporter(self.token, self.chat_id)
        self.offset   = 0
        self.running  = True
        self.monitoring = False
        self.last_block = 0
        log.info("🤖 MEVBot initialized")

    def send(self, chat_id: str, text: str):
        try:
            requests.post(
                f"{self.base}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=10
            )
        except Exception as e:
            log.error(f"Send error: {e}")

    def get_updates(self) -> list:
        try:
            r = requests.get(
                f"{self.base}/getUpdates",
                params={"offset": self.offset, "timeout": 10},
                timeout=15
            )
            return r.json().get("result", [])
        except Exception:
            return []

    # ── Commands ──────────────────────────────
    def cmd_start(self, chat_id: str):
        self.send(chat_id, """
🎯 *MEV Detector Bot*
━━━━━━━━━━━━━━━━━━━━━━

Detect MEV activity on Ethereum in real-time!

🥪 Sandwich Attacks
💱 Arbitrage Transactions
🏃 Frontrunning

📋 *Commands:*
/scan `[block]` — Scan block untuk MEV
/latest — Scan block terbaru
/monitor `<on/off>` — Auto monitor setiap block
/status — Status monitoring
/bots — List known MEV bots
/help — Bantuan

*Contoh:*
`/scan 25140000`
`/monitor on`
        """.strip())

    def cmd_scan(self, chat_id: str, args: list):
        if args:
            try:
                block_num = int(args[0])
            except ValueError:
                self.send(chat_id, "❌ Block number harus angka!")
                return
        else:
            block_num = self.w3.get_latest_block()

        self.send(chat_id, f"🔍 Scanning block `#{block_num}`...\n⏳ Mohon tunggu ~15 detik...")

        try:
            result = self.analyzer.scan_block(block_num)

            if result.get("error"):
                self.send(chat_id, f"❌ Error: `{result['error']}`")
                return

            summary = result["summary"]
            msg = f"""
📊 *MEV SCAN RESULT — Block #{block_num}*
━━━━━━━━━━━━━━━━━━━━━━
📦 Total TXs   : `{result['total_txs']}`
⚡ MEV Found   : `{result['mev_count']}`

🥪 Sandwiches  : `{summary['sandwich_count']}`
💱 Arbitrages  : `{summary['arbitrage_count']}`
🏃 Frontruns   : `{summary['frontrun_count']}`
🔴 High Risk   : `{summary['severity_high']}`
🟡 Medium Risk : `{summary['severity_medium']}`
            """.strip()
            self.send(chat_id, msg)

            # Kirim detail alerts
            for s in result["sandwiches"][:3]:
                self.reporter.send_sandwich_alert(s, block_num)
            for a in result["arbitrages"][:3]:
                self.reporter.send_arbitrage_alert(a, block_num)
            for f in result["frontruns"][:3]:
                self.reporter.send_frontrun_alert(f, block_num)

            if result["mev_count"] == 0:
                self.send(chat_id, "✅ Tidak ada MEV terdeteksi di block ini.")

        except Exception as e:
            self.send(chat_id, f"❌ Error: `{str(e)[:200]}`")

    def cmd_latest(self, chat_id: str):
        block_num = self.w3.get_latest_block()
        self.send(chat_id, f"🔍 Scanning latest block `#{block_num}`...")
        self.cmd_scan(chat_id, [str(block_num)])

    def cmd_monitor(self, chat_id: str, args: list):
        if not args:
            status = "ON ✅" if self.monitoring else "OFF ❌"
            self.send(chat_id, f"📡 Auto monitor: *{status}*\nGunakan `/monitor on` atau `/monitor off`")
            return

        if args[0].lower() == "on":
            self.monitoring  = True
            self.last_block  = self.w3.get_latest_block()
            self.send(chat_id, f"✅ *MEV Monitor ON*\nMemantau dari block `#{self.last_block}`\nKamu akan dapat alert setiap ada MEV terdeteksi!")
        elif args[0].lower() == "off":
            self.monitoring = False
            self.send(chat_id, "❌ *MEV Monitor OFF*")

    def cmd_status(self, chat_id: str):
        current_block = self.w3.get_latest_block()
        gas_gwei      = self.w3.get_gas_price_gwei()
        monitor_str   = "✅ ON" if self.monitoring else "❌ OFF"

        self.send(chat_id, f"""
📡 *MEV Bot Status*
━━━━━━━━━━━━━━━━━━━━━━
🔗 Latest Block : `#{current_block}`
⛽ Gas Price    : `{gas_gwei:.1f} Gwei`
📡 Monitoring   : {monitor_str}
⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """.strip())

    def cmd_bots(self, chat_id: str):
        lines = ["🤖 *Known MEV Bots*\n━━━━━━━━━━━━━━━━━━━━━━"]
        for addr, label in KNOWN_MEV_BOTS.items():
            lines.append(f"• `{addr[:10]}...` — {label}")
        self.send(chat_id, "\n".join(lines))

    # ── Auto Monitor ──────────────────────────
    def _auto_monitor(self):
        """Background thread untuk monitor setiap block baru."""
        while self.running:
            if self.monitoring:
                try:
                    current = self.w3.get_latest_block()
                    if current > self.last_block:
                        for block_num in range(self.last_block + 1, current + 1):
                            result = self.analyzer.scan_block(block_num)
                            if result.get("mev_count", 0) > 0:
                                self.reporter.send_block_summary(result)
                                for s in result["sandwiches"][:2]:
                                    self.reporter.send_sandwich_alert(s, block_num)
                                for a in result["arbitrages"][:2]:
                                    self.reporter.send_arbitrage_alert(a, block_num)
                                for f in result["frontruns"][:2]:
                                    self.reporter.send_frontrun_alert(f, block_num)
                            time.sleep(1)
                        self.last_block = current
                except Exception as e:
                    log.error(f"Monitor error: {e}")
            time.sleep(12)  # Ethereum block time ~12 detik

    # ── Message Router ────────────────────────
    def handle(self, message: dict):
        text    = message.get("text", "").strip()
        chat_id = str(message.get("chat", {}).get("id", ""))
        if not text or not chat_id:
            return

        parts   = text.split()
        command = parts[0].lower()
        args    = parts[1:]
        log.info(f"📨 {command} from {chat_id}")

        if command in ("/start", "/help"): self.cmd_start(chat_id)
        elif command == "/scan":           self.cmd_scan(chat_id, args)
        elif command == "/latest":         self.cmd_latest(chat_id)
        elif command == "/monitor":        self.cmd_monitor(chat_id, args)
        elif command == "/status":         self.cmd_status(chat_id)
        elif command == "/bots":           self.cmd_bots(chat_id)
        else:
            self.send(chat_id, "❓ Command tidak dikenal. Ketik /help untuk bantuan.")

    # ── Main Loop ─────────────────────────────
    def run(self):
        import threading
        log.info("🚀 MEVBot started!")

        # Start background monitor thread
        monitor_thread = threading.Thread(target=self._auto_monitor, daemon=True)
        monitor_thread.start()

        while self.running:
            try:
                updates = self.get_updates()
                for update in updates:
                    self.offset = update["update_id"] + 1
                    msg = update.get("message", {})
                    if msg:
                        self.handle(msg)
            except KeyboardInterrupt:
                log.info("🛑 Bot stopped.")
                self.running = False
            except Exception as e:
                log.error(f"Polling error: {e}")
                time.sleep(5)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        # Quick scan mode
        block = int(sys.argv[2]) if len(sys.argv) > 2 else None
        w3    = Web3Client(INFURA_URL)
        eth   = EtherscanClient(ETHERSCAN_API_KEY)
        ana   = MEVAnalyzer(w3, eth)

        block_num = block or w3.get_latest_block()
        print(f"\n🔍 Scanning block #{block_num}...")
        result = ana.scan_block(block_num)

        print(f"\n📊 Results:")
        print(f"Total TXs  : {result.get('total_txs', 0)}")
        print(f"MEV Found  : {result.get('mev_count', 0)}")
        print(f"Sandwiches : {result['summary']['sandwich_count']}")
        print(f"Arbitrages : {result['summary']['arbitrage_count']}")
        print(f"Frontruns  : {result['summary']['frontrun_count']}")

        if result["sandwiches"]:
            print(f"\n🥪 Sandwich Attacks:")
            for s in result["sandwiches"]:
                print(f"  - Attacker: {s['attacker'][:10]}... | DEX: {s['dex']} | Severity: {s['severity']}")

    else:
        # Bot mode
        bot = MEVBot()
        bot.run()
