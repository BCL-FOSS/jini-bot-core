#!/bin/sh

nohup chroma run --path /home/quart/utils/chromadb_data --port 6000 > /var/log/chroma.log 2>&1 &

uvicorn app:app --host 0.0.0.0 --port 8000