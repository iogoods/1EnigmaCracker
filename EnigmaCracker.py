import aiohttp
from aiogram import Bot
import asyncio
from datetime import datetime, timedelta
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip39WordsNum
import logging
import concurrent.futures
import os
import sys
import random

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

# Liste öffentlicher ElectrumX-Server (mit Portnummern)
ELECTRUMX_SERVERS = [
    'erbium1.sytes.net',
    'ecdsa.net',
    'gh05.geekhosters.com',
    'VPS.hsmiths.com',
    'electrum.anduck.net',
    'electrum.no-ip.org',
    'electrum.be',
    'helicarrier.bauerj.eu',
    'elex01.blackpole.online',
    'electrumx.not.fyi',
    'node.xbt.eu',
    'kirsche.emzy.de',
    'electrum.villocq.com',
    'us11.einfachmalnettsein.de',
    'electrum.trouth.net',
    'Electrum.hsmiths.com',
    'electrum3.hachre.de',
    'b.1209k.com',
    'elec.luggs.co',
    'btc.smsys.me'
]

DEFAULT_PORTS = {'core': '50001', 'ssl': '50002'}

# Performance-Einstellungen
MAX_WORKERS = 10
BATCH_SIZE = 5
TIMEOUT_SECONDS = 10
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

async def check_btc_balance_async(address, session, retries=3, delay=5):
    """Prüfe den BTC-Saldo einer Adresse mit Wiederholungsversuchen und Debugging."""
    # Wähle zufällig einen öffentlichen ElectrumX-Server aus
    server = random.choice(ELECTRUMX_SERVERS)
    port = DEFAULT_PORTS['core']  # Normalerweise verwenden wir den Standard-Port
    url = f'http://{server}:{port}'  # URL für den Server

    json_data = {
        "jsonrpc": "2.0",
        "method": "blockchain.address.get_balance",
        "params": [address],
        "id": 1  # Verwende 1 für id, um den Fehler zu vermeiden
    }
    
    # Debugging: Ausgabe der Anfrage
    logger.debug(f"JSON Anfrage an {url}: {json_data}")

    for attempt in range(retries):
        try:
            async with session.post(url, json=json_data) as response:
                # Ausgabe der Serverantwort für Debugging
                response_data = await response.json()
                logger.debug(f"Antwort vom Server {url}: {response_data}")
                
                if response.status == 200:
                    if "result" in response_data:
                        balance = response_data["result"]["confirmed"] / 100000000  # Von Satoshi in BTC umrechnen
                        logger.info(f"Balance für Adresse {address}: {balance} BTC")
                        return balance
                    else:
                        logger.warning(f"Kein Ergebnis für Adresse {address}. Antwort: {response_data}")
                else:
                    logger.warning(f"Fehler beim Abrufen der Balance für {address}. HTTP-Status: {response.status}")
        except Exception as e:
            logger.error(f"Fehler beim Prüfen der Balance für Adresse {address} (Versuch {attempt + 1}): {e}")
            if attempt < retries - 1:
                logger.info(f"Erneuter Versuch in {delay} Sekunden...")
                await asyncio.sleep(delay)
            else:
                logger.error(f"Maximale Anzahl an Versuchen erreicht. Kann Balance nicht prüfen.")
    return 0

async def process_wallet_async(seed, session, messages):
    """Verarbeite eine Wallet asynchron mit Debugging-Logs."""
    btc_address = bip44_btc_address_from_seed(seed)
    logger.info(f"Erzeugte Adresse {btc_address} aus Seed: {seed}")
    
    # Prüfe die Balance
    btc_balance = await check_btc_balance_async(btc_address, session)

    if btc_balance > 0:
        message = f"⚠️ Wallet mit Guthaben gefunden!\nSeed: {seed}\nAdresse: {btc_address}\nGuthaben: {btc_balance} BTC"
        messages.append(message)
        logger.info(f"Guthaben für Adresse {btc_address}: {btc_balance} BTC gefunden.")

async def seed_generator(queue, num_seeds):
    """Erzeuge Seeds parallel und füge sie der Queue hinzu mit Debugging."""
    with concurrent.futures.ProcessPoolExecutor() as executor:
        loop = asyncio.get_running_loop()
        tasks = [loop.run_in_executor(executor, generate_bip39_seed) for _ in range(num_seeds)]
        for task in asyncio.as_completed(tasks):
            seed = await task
            logger.debug(f"Erzeugter Seed: {seed}")
            await queue.put(seed)
    await queue.put(None)

async def worker(queue, session, messages):
    """Verarbeitungs-Worker für Wallets mit Debugging-Logs."""
    while True:
        seed = await queue.get()
        if seed is None:
            queue.put_nowait(None)
            break
        await process_wallet_async(seed, session, messages)
        queue.task_done()

async def dynamic_batch_manager():
    """Passe die Batch-Größe dynamisch an."""    
    global BATCH_SIZE
    while True:
        await asyncio.sleep(60)  # Alle 60 Sekunden prüfen
        if BATCH_SIZE < MAX_WORKERS:
            BATCH_SIZE += 1  # Bei schnellen Serverantworten erhöhen
        logger.debug(f"Aktuelle Batch-Größe: {BATCH_SIZE}")

async def daily_summary():
    """Sende eine tägliche Zusammenfassung."""
    wallets_scanned_today = 0
    while True:
        now = datetime.now()
        next_run = (now + timedelta(days=1)).replace(hour=DAILY_RESET_HOUR, minute=0)
        await asyncio.sleep((next_run - now).total_seconds())
        summary_message = f"📊 Tägliche Wallet-Scan-Zusammenfassung:\nInsgesamt gescannte Wallets heute: {wallets_scanned_today}"
        await notify_telegram_async([summary_message])
        wallets_scanned_today = 0  # Reset für den nächsten Tag

async def main_async():
    """Main-Funktion für das Wallet-Scannen."""
    queue = asyncio.Queue()
    messages = []
    tasks = []

    async with aiohttp.ClientSession() as session:
        tasks.append(asyncio.create_task(seed_generator(queue, BATCH_SIZE)))
        tasks.append(asyncio.create_task(worker(queue, session, messages)))
        tasks.append(asyncio.create_task(dynamic_batch_manager()))
        tasks.append(asyncio.create_task(daily_summary()))
        tasks.append(asyncio.create_task(reset_log_daily()))

        # Warte darauf, dass alle Tasks abgeschlossen sind
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main_async())
