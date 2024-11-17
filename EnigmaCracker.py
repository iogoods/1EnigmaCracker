import aiohttp
import asyncio
from aiogram import Bot
from datetime import datetime, timedelta
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip39WordsNum
import logging
import sys
import time

# Logger-Konfiguration
LOG_FILE = "wallet_scanner.log"

# Logger erstellen
logger = logging.getLogger("wallet_scanner")
logger.setLevel(logging.DEBUG)  # Log-Level auf DEBUG setzen (für detaillierte Logs)

# Konsole-Handler
console_handler = logging.StreamHandler(sys.stdout)  # Logs in die Konsole
console_handler.setLevel(logging.DEBUG)  # DEBUG-Level für die Konsole
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Datei-Handler
file_handler = logging.FileHandler(LOG_FILE)  # Logs in eine Datei schreiben
file_handler.setLevel(logging.INFO)  # INFO-Level für die Datei
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

# Logger mit beiden Handlern konfigurieren
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Telegram und ElectrumX-Konfiguration
TELEGRAM_TOKEN = "7706620947:AAGLGdTIKi4dB3irOtVmHD57f1Xxa8-ZIcs"
TELEGRAM_CHAT_ID = "1596333326"
ELECTRUMX_SERVER_URL = "http://127.0.0.1:50001"  # Für SSL auf https:// ändern

# Performance-Einstellungen
MAX_WORKERS = 1  # Auf 1 setzen, damit die Adressen nacheinander überprüft werden
TIMEOUT_SECONDS = 30  # Timeout auf 30 Sekunden erhöhen
DAILY_RESET_HOUR = 0

# Telegram-Bot initialisieren
bot = Bot(token=TELEGRAM_TOKEN)


async def reset_log_daily():
    """Tägliches Zurücksetzen der Log-Datei."""
    while True:
        now = datetime.now()
        next_run = (now + timedelta(days=1)).replace(hour=DAILY_RESET_HOUR, minute=0, second=0, microsecond=0)
        await asyncio.sleep((next_run - now).total_seconds())
        
        # Log-Datei leeren
        with open(LOG_FILE, "w"):
            pass  # Öffnen und sofort schließen, um die Datei zu leeren
        logger.info("Log-Datei wurde um Mitternacht zurückgesetzt.")


async def notify_telegram_async(messages):
    """Sende Benachrichtigungen an Telegram."""
    combined_message = "\n\n".join(messages)
    try:
        await bot.send_message(TELEGRAM_CHAT_ID, combined_message)
        logger.info("Nachricht an Telegram gesendet.")
    except Exception as e:
        logger.error(f"Fehler beim Senden an Telegram: {e}")


def generate_bip39_seed():
    """Generiere eine zufällige BIP39-Seed-Phrase."""
    return Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)


def bip44_btc_address_from_seed(seed_phrase):
    """Erzeuge eine Bitcoin-Adresse aus einer BIP39-Seed-Phrase."""
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(0)
    return bip44_addr_ctx.PublicKey().ToAddress()


async def check_btc_balance_async(address, session):
    """Prüfe den BTC-Saldo einer Adresse asynchron über den ElectrumX-Server mit Retry-Logik."""
    url = ELECTRUMX_SERVER_URL
    json_data = {
        "jsonrpc": "2.0",
        "method": "blockchain.address.get_balance",
        "params": [address],
        "id": 1
    }
    logger.info(f"Prüfe Balance für Adresse: {address}")
    
    retries = 3  # Maximale Anzahl an Versuchen
    for attempt in range(retries):
        try:
            async with session.post(url, json=json_data) as response:
                if response.status == 200:
                    data = await response.json()
                    if "result" in data:
                        balance = data["result"]["confirmed"] / 100000000  # Von Satoshi in BTC umrechnen
                        logger.info(f"Balance für Adresse {address}: {balance} BTC")
                        return balance
                    else:
                        logger.warning(f"Kein Ergebnis für Adresse {address}. Antwort: {data}")
                else:
                    logger.warning(f"Fehler beim Abrufen der Balance für {address}. HTTP-Status: {response.status}")
        except Exception as e:
            logger.error(f"Fehler beim Prüfen der Balance für Adresse {address} (Versuch {attempt + 1}): {e}")
            if attempt < retries - 1:
                logger.info(f"Versuche es in 5 Sekunden erneut... (Versuch {attempt + 1})")
                await asyncio.sleep(5)  # Verzögerung von 5 Sekunden vor dem nächsten Versuch
            else:
                logger.error(f"Maximale Anzahl an Versuchen erreicht. Fehler konnte nicht behoben werden.")
    
    return 0


async def process_wallet_async(seed, session, messages):
    """Verarbeite eine Wallet asynchron."""
    btc_address = bip44_btc_address_from_seed(seed)
    logger.info(f"Erzeugte Adresse {btc_address} aus Seed: {seed}")
    btc_balance = await check_btc_balance_async(btc_address, session)
    
    if btc_balance > 0:
        message = f"⚠️ Wallet mit Guthaben gefunden!\nSeed: {seed}\nAdresse: {btc_address}\nGuthaben: {btc_balance} BTC"
        messages.append(message)
        logger.info(f"Guthaben für Adresse {btc_address}: {btc_balance} BTC gefunden.")


async def seed_generator(num_seeds):
    """Erzeuge Seeds und gebe sie zurück."""
    seeds = [generate_bip39_seed() for _ in range(num_seeds)]
    return seeds


async def main_async():
    """Hauptfunktion zur Verarbeitung der Wallets."""
    num_seeds = 50  # Anzahl der zu überprüfenden Wallets
    messages = []
    
    # Seeds erzeugen
    seeds = await seed_generator(num_seeds)

    connector = aiohttp.TCPConnector(limit=MAX_WORKERS)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)) as session:
        # Nacheinander die Wallets prüfen
        for seed in seeds:
            await process_wallet_async(seed, session, messages)

        if messages:
            await notify_telegram_async(messages)
            messages.clear()


if __name__ == "__main__":
    asyncio.run(main_async())
