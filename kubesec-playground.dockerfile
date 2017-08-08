# https://hub.docker.com/r/shyiko/kubesec-playground/
#
# This image contains:
# - 1 PGP secret key (FOR TESTING PURPOSES ONLY)
#   6206C32E111611688694CF5530BDA87E3E71C268 Jean-Luc Picard <jean-luc.picard@uss-enterprise-d.starfleet>
# - 1 imported (3rd party) public key
#   160A7A9CF46221A56B06AD64461A804F2609FD89 Stanley Shyiko <stanley.shyiko@gmail.com>
# + gpg2.1+, kubesec, vim (as a default $EDITOR) and ktmpl (in case you want to try 2nd example from readme)
#
# Usage:
# docker run -it --rm shyiko/kubesec-playground:latest /bin/bash
# $ kubesec encode secret.yml

FROM ubuntu:16.04

RUN apt-get update && apt-get install -y curl gnupg2 vim && rm -rf /var/lib/apt/lists/*

COPY jean-luc.picard.pubkey /root/
COPY jean-luc.picard.seckey /root/

WORKDIR /root

RUN gpg2 --import jean-luc.picard.pubkey && \
    gpg2 --allow-secret-key-import --import jean-luc.picard.seckey

# import https://keybase.io/shyiko's public key
RUN gpg2 --keyserver pgp.mit.edu --recv-keys 461A804F2609FD89
# printf "trust\n5\ny\n" > gpg-trust.cmd && gpg2 --command-file gpg-trust.cmd --edit-key 461A804F2609FD89

RUN curl -sSL https://github.com/InQuicker/ktmpl/releases/download/0.7.0/ktmpl-0.7.0-linux.tar.gz | tar -xzf - &&\
    mv ktmpl /usr/local/bin

RUN curl -sSL https://github.com/mikefarah/yaml/releases/download/1.11/yaml_linux_amd64 -o /usr/local/bin/yaml &&\
    chmod a+x /usr/local/bin/yaml

# RUN curl -sSL https://github.com/shyiko/kubesec/releases/download/0.1.0/kubesec-0.1.0-$(\
#     bash -c '[ $OSTYPE = darwin* ] && echo darwin || echo linux'\
#   )-amd64 > kubesec &&\
#   chmod a+x kubesec &&\
#   curl -sSL https://github.com/shyiko/kubesec/releases/download/0.1.0/kubesec-0.1.0-$(\
#       bash -c '[ $OSTYPE = darwin* ] && echo darwin || echo linux'\
#     ).asc > kubesec.asc &&\
#   gpg --verify kubesec.asc &&\
#   mv kubesec /usr/local/bin
#
# # sample Secret resource
# RUN echo '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"app-stable-0"},"type":"Opaque",\
#     "data":{"KEY":"dmFsdWUK","ANOTHER_KEY":"YW5vdGhlcl92YWx1ZQo="}}' | kubesec encrypt > secret.yml

COPY README.md/ /root/
