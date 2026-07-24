FROM python:3.12

RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y \
      git \
 && rm -rf /var/lib/apt/lists/*

RUN adduser quart --disabled-password 

WORKDIR /home/quart

RUN apt-get update -y

RUN apt-get upgrade -y

COPY backend/requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ /home/quart/

RUN chmod +x boot.sh 

ENTRYPOINT ["sh", "./boot.sh"]