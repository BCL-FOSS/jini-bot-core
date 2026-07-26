#!/bin/sh

nohup /opt/telegram-bot-api/bin/telegram-bot-api --api-id "$TELEGRAM_API_ID" --api-hash "$TELEGRAM_API_HASH" --local > /var/log/telegram_bot_api.log 2>&1 &

nohup python3 -m utils.TelegramBot > /var/log/TelegramBot.log 2>&1 &

uvicorn app:app --host 0.0.0.0 --port 5000