FROM python:3.12

RUN adduser quart --disabled-password 

WORKDIR /home/quart

RUN apt-get update -y

RUN apt-get upgrade -y

COPY backend/requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ /home/quart/

WORKDIR /home/quart/utils

RUN git clone https://github.com/BCL-FOSS/cli-parser.git

RUN chmod +x boot.sh 

ENTRYPOINT ["sh", "./boot.sh"]