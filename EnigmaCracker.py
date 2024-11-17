import aiohttp
import ssl
import asyncio
import logging
from datetime import datetime, timedelta
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip39WordsNum

# Logger-Konfiguration
LOG_FILE = "wallet_scanner.log"
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", filename=LOG_FILE)
logger = logging.getLogger()

# Telegram- und ElectrumX-Server-Konfiguration
TELEGRAM_TOKEN = "7706620947:AAGLGdTIKi4dB3irOtVmHD57f1Xxa8-ZIcs"
TELEGRAM_CHAT_ID = "1596333326"
ELECTRUMX_SERVER_URL = "https://127.0.0.1:50002"  # SSL-Port verwenden

# Maximale Anzahl paralleler Verbindungen
MAX_WORKERS = 10
TIMEOUT_SECONDS = 10

# SSL-Kontext: SSL-Zertifikatsprüfung deaktivieren
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

async def check_btc_balance_async(address, session):
    """Überprüfe den BTC-Saldo einer Adresse asynchron."""
    url = f"{ELECTRUMX_SERVER_URL}/balance/{address}"
    logger.info(f"Checking balance for address: {address}")
    try:
        async with session.get(url, ssl=ssl_context) as response:  # SSL-Überprüfung deaktivieren
            if response.status == 200:
                data = await response.json()
                balance = data.get("confirmed", 0) / 100000000  # Satoshi in BTC umwandeln
                logger.info(f"Balance for address {address}: {balance} BTC")
                return balance
            else:
                logger.warning(f"Failed to fetch balance for {address}. HTTP Status: {response.status}")
    except Exception as e:
        logger.error(f"Error checking balance for address {address}: {e}")
    return 0

async def process_wallet_async(seed, session, messages):
    """Verarbeite ein Wallet asynchron."""
    try:
        seed_phrase = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
        bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
        bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
        btc_address = bip44_chg_ctx.AddressIndex(0).PublicKey().ToAddress()

        logger.info(f"Generated address {btc_address} from seed: {seed_phrase}")
        btc_balance = await check_btc_balance_async(btc_address, session)

        if btc_balance > 0:
            message = f"⚠️ Wallet with balance found!\nSeed: {seed_phrase}\nAddress: {btc_address}\nBalance: {btc_balance} BTC"
            messages.append(message)
            logger.info(message)
    except Exception as e:
        logger.error(f"Error processing wallet: {e}")

async def main_async():
    """Hauptfunktion."""
    messages = []
    connector = aiohttp.TCPConnector(limit=MAX_WORKERS)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)) as session:
        seed_tasks = [asyncio.create_task(process_wallet_async(None, session, messages)) for _ in range(10)]
        await asyncio.gather(*seed_tasks)

    # Nachrichten ausgeben
    if messages:
        for msg in messages:
            print(msg)

if __name__ == "__main__":
    asyncio.run(main_async())
