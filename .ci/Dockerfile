FROM golang:1.8

RUN apt-get update && apt-get install -y gnupg2 && rm -rf /var/lib/apt/lists/*

COPY jean-luc.picard.pubkey /root/
COPY jean-luc.picard.seckey /root/

WORKDIR /root

RUN gpg2 --import jean-luc.picard.pubkey && \
    gpg2 --allow-secret-key-import --import jean-luc.picard.seckey

RUN gpg2 --keyserver pgp.mit.edu --recv-keys \
    160A7A9CF46221A56B06AD64461A804F2609FD89 \
    72ECF46A56B4AD39C907BBB71646B01B86E50310
