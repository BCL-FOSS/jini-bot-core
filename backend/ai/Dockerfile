FROM python:3.12

RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
      make git zlib1g-dev libssl-dev gperf cmake g++ \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt
RUN git clone --recursive https://github.com/tdlib/telegram-bot-api.git \
 && cd telegram-bot-api \
 && rm -rf build \
 && mkdir build \
 && cd build \
 && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=.. .. \
 && cmake --build . --target install
RUN ls -l /opt/telegram-bot-api/bin/telegram-bot-api* || true

RUN adduser quart --disabled-password 
WORKDIR /home/quart
RUN apt-get update -y
RUN apt-get upgrade -y
COPY backend/ai/smartbot/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ai/ /home/quart/
RUN mkdir /home/quart/utils/chromadb_data
RUN chmod +x boot.sh 

ENTRYPOINT ["sh", "./boot.sh"]