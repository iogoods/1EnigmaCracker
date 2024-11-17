import aiohttp
from aiogram import Bot
import asyncio
from datetime import datetime, timedelta
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip39WordsNum
import logging
import concurrent.futures
import os

# Logger configuration
LOG_FILE = "wallet_scanner.log"
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", filename=LOG_FILE)
logger = logging.getLogger()

# Telegram and ElectrumX server configuration
TELEGRAM_TOKEN = "7706620947:AAGLGdTIKi4dB3irOtVmHD57f1Xxa8-ZIcs"
TELEGRAM_CHAT_ID = "1596333326"
ELECTRUMX_SERVER_URL = "http://127.0.0.1:50001"

# Performance and concurrency settings
MAX_WORKERS = 10
BATCH_SIZE = 5
TIMEOUT_SECONDS = 10
DAILY_RESET_HOUR = 0

# Initialize the bot
bot = Bot(token=TELEGRAM_TOKEN)

async def reset_log_daily():
    """Clear the log file daily at midnight."""
    while True:
        now = datetime.now()
        next_run = (now + timedelta(days=1)).replace(hour=DAILY_RESET_HOUR, minute=0, second=0, microsecond=0)
        await asyncio.sleep((next_run - now).total_seconds())
        
        # Clear log file
        with open(LOG_FILE, "w"):
            pass  # Open and immediately close the file to clear its contents
        logger.info("Log file reset at midnight")

async def notify_telegram_async(messages):
    """Send batch notifications to Telegram asynchronously."""
    combined_message = "\n\n".join(messages)
    await bot.send_message(TELEGRAM_CHAT_ID, combined_message)

def generate_bip39_seed():
    """Generate a random BIP39 seed."""
    return Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)

def bip44_btc_address_from_seed(seed_phrase):
    """Generate a Bitcoin address from a BIP39 seed."""
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(0)
    return bip44_addr_ctx.PublicKey().ToAddress()

async def check_btc_balance_async(address, session):
    """Check the BTC balance of an address asynchronously using ElectrumX server."""
    url = f"{ELECTRUMX_SERVER_URL}/balance/{address}"
    logger.info(f"Checking balance for address: {address}")  # Log each address check
    try:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                balance = data.get("confirmed", 0) / 100000000  # Convert from Satoshi to BTC
                logger.info(f"Balance for address {address}: {balance} BTC")  # Log the balance
                return balance
            else:
                logger.warning(f"Failed to fetch balance for {address}. HTTP Status: {response.status}")
    except Exception as e:
        logger.error(f"Error checking balance for address {address}: {e}")
    return 0

async def process_wallet_async(seed, session, messages):
    """Process a single wallet asynchronously."""
    btc_address = bip44_btc_address_from_seed(seed)
    logger.info(f"Generated address {btc_address} from seed: {seed}")  # Log the generated address and seed
    btc_balance = await check_btc_balance_async(btc_address, session)
    
    # Notify if balance is found
    if btc_balance > 0:
        message = f"⚠️ Wallet with balance found!\nSeed: {seed}\nAddress: {btc_address}\nBalance: {btc_balance} BTC"
        messages.append(message)
        logger.info(f"Found balance for address {btc_address}: {btc_balance} BTC")  # Log positive balances

async def seed_generator(queue, num_seeds):
    """Generate seeds in parallel using ProcessPoolExecutor and put them in a queue."""
    with concurrent.futures.ProcessPoolExecutor() as executor:
        loop = asyncio.get_running_loop()
        tasks = [loop.run_in_executor(executor, generate_bip39_seed) for _ in range(num_seeds)]
        for task in asyncio.as_completed(tasks):
            seed = await task
            logger.info(f"Generated seed: {seed}")  # Log each generated seed
            await queue.put(seed)
    await queue.put(None)

async def worker(queue, session, messages):
    """Worker task to process wallets."""
    while True:
        seed = await queue.get()
        if seed is None:
            queue.put_nowait(None)
            break
        await process_wallet_async(seed, session, messages)
        queue.task_done()

async def dynamic_batch_manager():
    """Adjust batch size dynamically based on response times."""
    global BATCH_SIZE
    while True:
        await asyncio.sleep(60)  # Adjust every 60 seconds
        if BATCH_SIZE < MAX_WORKERS:
            BATCH_SIZE += 1  # Scale up if server responds quickly

async def daily_summary():
    """Send a daily summary of wallets processed."""
    wallets_scanned_today = 0
    while True:
        now = datetime.now()
        next_run = (now + timedelta(days=1)).replace(hour=DAILY_RESET_HOUR, minute=0)
        await asyncio.sleep((next_run - now).total_seconds())
        
        # Send the daily summary
        summary_message = f"📊 Daily Wallet Scan Summary:\nTotal wallets scanned today: {wallets_scanned_today}"
        await notify_telegram_async([summary_message])
        
        # Reset the daily counter
        wallets_scanned_today = 0

async def main_async():
    """Main function to process wallets and send notifications."""
    queue = asyncio.Queue()
    num_seeds = 50
    messages = []
    
    # Start async background tasks
    asyncio.create_task(dynamic_batch_manager())
    asyncio.create_task(daily_summary())
    asyncio.create_task(reset_log_daily())  # Schedule daily log reset
    
    connector = aiohttp.TCPConnector(limit=MAX_WORKERS)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)) as session:
        seed_task = asyncio.create_task(seed_generator(queue, num_seeds))
        worker_tasks = [asyncio.create_task(worker(queue, session, messages)) for _ in range(MAX_WORKERS)]
        
        await seed_task
        await queue.join()
        
        # Send batch notifications every few minutes if messages exist
        if messages:
            await notify_telegram_async(messages)
            messages.clear()
        
        # Cancel worker tasks
        for task in worker_tasks:
            task.cancel()
        await asyncio.gather(*worker_tasks, return_exceptions=True)

if __name__ == "__main__":
    asyncio.run(main_async())
