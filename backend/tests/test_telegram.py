"""
Test script for Telegram notification
"""
import asyncio
import sys
sys.path.append('.')  # Add project root to path

from app.services.telegram_notifier import TelegramNotifier
from app.core.config import settings

async def test_telegram():
    """Test the Telegram notifier"""
    print("📤 Testing Telegram notification...")
    
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        print("❌ Telegram not configured in .env")
        return
    
    notifier = TelegramNotifier(
        settings.TELEGRAM_BOT_TOKEN,
        settings.TELEGRAM_CHAT_ID
    )
    
    result = await notifier.send_test_message()
    
    if result:
        print("✅ Test message sent! Check your Telegram @AciipBot")
    else:
        print("❌ Failed to send test message")

if __name__ == "__main__":
    asyncio.run(test_telegram())