This directory contains PGP keys used by Travis CI and [shyiko/kubesec-playground](https://hub.docker.com/r/shyiko/kubesec-playground/).  
Originally generated with:

```sh
docker run -it --rm -v $(pwd):/workdir -w /workdir golang:1.8 /bin/bash

# everything below is meant to be executed inside the docker container

apt-get update && apt-get install -y gnupg2 && rm -rf /var/lib/apt/lists/*
gpg2 --version

    gpg (GnuPG) 2.0.26
    libgcrypt 1.6.3

# https://www.gnupg.org/documentation/manuals/gnupg-2.0/Unattended-GPG-key-generation.html
printf "Key-Type: default\nSubkey-Type: default\nExpire-Date: 0\nName-Real: Jean-Luc Picard
Name-Email: jean-luc.picard@uss-enterprise-d.starfleet\n%%no-protection\n" > /tmp/key.template
gpg2 --batch --gen-key /tmp/key.template

# --export-secret-key is broken on gpg 2.1 (see gpg2 --version above) 
gpg2 --export-secret-key > jean-luc.picard.seckey
gpg2 --export > jean-luc.picard.pubkey    
```
