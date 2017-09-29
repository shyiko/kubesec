# kubesec ![Latest Version](https://img.shields.io/badge/latest-0.3.1-blue.svg) [![Build Status](https://travis-ci.org/shyiko/kubesec.svg?branch=master)](https://travis-ci.org/shyiko/kubesec)

Secure secret management for [Kubernetes](https://kubernetes.io/) (with [gpg](https://gnupg.org/), 
[Google Cloud KMS](https://cloud.google.com/kms/) and [AWS KMS](https://aws.amazon.com/kms/) backends).

[![asciicast](https://asciinema.org/a/YCUk0q7e3qUi6kjqJq9NQdt6c.png)](https://asciinema.org/a/YCUk0q7e3qUi6kjqJq9NQdt6c)  
  
In short, it allows you to encrypt [Secret](https://kubernetes.io/docs/concepts/configuration/secret/)s so that they can be stored in VCS along 
with the rest of resources.  
An example of encrypted Secret is shown below (note that only the "data" is encrypted (and that keys are left untouched)): 

```yml
apiVersion: v1
kind: Secret
metadata:
  name: myapp-default-0
type: Opaque
data:
  KEY: TUFkWD1iuKs=.O....D...=
  ANOTHER_KEY: iOy1nf90+M6FrrEIoymN6cOSUYM=.E...=.q...=
# ...  
```

The nice thing about this approach (compared to complete file encryption) is that `git diff` and `git merge` become
so much more user-friendly (+ you can ascertain that specific entry is present even if you don't have the key to decrypt the secret).

`kubesec` is written in Go, works with (or without) [Yubikey](https://www.yubico.com/) ❤. 

> For general-purpose secret management, take a look at [mozilla/sops](https://github.com/mozilla/sops)   
(`kubesec`'s drawn a lot of inspiration from it). 

## Installation

#### macOS / Linux

```sh
curl -sSL https://github.com/shyiko/kubesec/releases/download/0.3.1/kubesec-0.3.1-$(
    bash -c '[[ $OSTYPE == darwin* ]] && echo darwin || echo linux'
  )-amd64 > kubesec && chmod a+x kubesec
    
# verify PGP signature (optional but RECOMMENDED)
curl -sSL https://github.com/shyiko/kubesec/releases/download/0.3.1/kubesec-0.3.1-$(
    bash -c '[[ $OSTYPE == darwin* ]] && echo darwin || echo linux'
  )-amd64.asc > kubesec.asc
curl https://keybase.io/shyiko/pgp_keys.asc | gpg --import
gpg --verify kubesec.asc
```  

#### Windows

Download binary from the "[release(s)](https://github.com/shyiko/kubesec/releases)" page.

## Usage

> **GPG USERS ONLY**: [gpg](https://gnupg.org/) (tested: 2.0+; recommended: 2.1+) **must** be available on the PATH.   
It's also highly recommended to set up [gpg-agent](https://wiki.archlinux.org/index.php/GnuPG#gpg-agent) to avoid 
constant passphrase re-entry.    

```sh
# encrypt a Secret
kubesec encrypt secret.yml
# same as above but output is written back to secret.yml (instead of stdout)
kubesec encrypt -i secret.yml

# NOTE: if you don't specify --key - default PGP key will be used
# in other words, `kubesec encrypt secret.yml` is identical to 
kubesec encrypt --key=pgp:default secret.yml

# NOTE: multiple --key|s can be specified if needed 
# (and they don't have to be of the same type, i.e. `--key=pgp:... --key=arn:...` 
# is perfectly valid)

# encrypt with PGP key ("pgp:" prefix is optional)
kubesec encrypt --key=pgp:6206C32E111611688694CF5530BDA87E3E71C268 secret.yml

# encrypt with Google Cloud KMS key ("gcp:" prefix is optional)
#
# NOTE: you'll need either to `gcloud auth application-default login` or set
# GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json 
# before attempting secret encryption/decryption
#
# https://developers.google.com/identity/protocols/application-default-credentials#howtheywork
kubesec encrypt --key=gcp:<resource-id of Google Cloud KMS key> secret.yml
kubesec encrypt \ 
  --key=gcp:projects/project-0/locations/global/keyRings/keyring-0/cryptoKeys/key-0 secret.yml

# encrypt with AWS KMS key ("aws:" prefix is optional)
#
# NOTE: you might need to `aws configure` (if you don't have ~/.aws/credentials already)
#
# http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
kubesec encrypt --key=aws:<ARN of AWS KMS key> secret.yml
kubesec encrypt \
  --key=aws:arn:aws:kms:us-west-1:000000000000:key/00000000-0000-0000-0000-000000000000 secret.yml

# add ...D89 key & drop ...310 key (leave all other keys untouched)
kubesec encrypt --key=+pgp:160A7A9CF46221A56B06AD64461A804F2609FD89 \
  --key=-pgp:6206C32E111611688694CF5530BDA87E3E71C268 secret.yml
# NOTE: removal of a key will automatically result in data encryption key rotation
# you will also need to change all the secrets as whoever you removed from the chain of trust might 
# still have access to the previous version of a file   

# encrypt content of stdin
cat secret.yml | kubesec encrypt -

# decrypt a Secret 
# (usually combined with kubectl (`kubesec decrypt secret.enc.yml | kubectl apply -f -`))
kubesec decrypt secret.enc.yml 

# open decrypted Secret in $EDITOR (it will be automatically re-encrypted upon save)
kubesec edit -i secret.enc.yml
kubesec edit -i --key=<a_different_key_to_re-encrypt-with> secret.enc.yml
# same as above but secret.enc.yml will be created if it doesn't exist 
kubesec edit -if secret.enc.yml

# show information about the Secret (who has access to the "data", last modification date, etc)
kubesec introspect secret.enc.yml
```

> `-` can be used anywhere (where a file is expected) to reference `stdin`.  
> (for more information see `kubesec --help`)

## Playground

If you have `docker` installed you don't need to download `kubesec` binary just to try it out.  
Instead, launch a container and start playing: 

```sh
docker run -it --rm shyiko/kubesec-playground:0.3.1-with-kubetpl-0.1.0 /bin/bash
$ kubesec encrypt secret.yml
```

> `shyiko/kubesec-playground` image contains `gpg` 2.1+, kubesec, vim (as a default $EDITOR) and 
  secret PGP key of Jean-Luc Picard (PGP fingerprint - 6206C32E111611688694CF5530BDA87E3E71C268). 

> Dockerfile [is included within this repo](kubesec-playground.dockerfile).

## Example(s)
 
If you don't have a valid PGP key, see [GitHub Help - Generating a new GPG key](https://help.github.com/articles/generating-a-new-gpg-key/#platform-linux) on 
how to generate one. 
 
#### #1 (basic)

```sh
echo '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"myapp-stable-0"},"type":"Opaque",
  "data":{"KEY":"dmFsdWUK","ANOTHER_KEY":"YW5vdGhlcl92YWx1ZQo="}}' | 
  kubesec encrypt -o secret.enc.yml
kubesec edit -i secret.enc.yml 
kubesec decrypt secret.enc.yml | kubectl apply -f - 
```

#### #2 (client-side templating)

> We'll use [kubetpl](https://github.com/shyiko/kubetpl), `kind: Template` flavour. You are free to choose any other format (or tool).    

Let's say we have the following (click to expand):

<details>
  <summary>&lt;project_dir&gt;/k8s/template.yml</summary>
  
```yml
# snippet:k8s/template.yml
apiVersion: v1
kind: Template
metadata:
  name: template
objects:
- apiVersion: v1
  kind: Pod
  metadata:
    name: $(NAME)-$(INSTANCE)
    labels: 
      app: $(NAME)
      instance: $(INSTANCE)
  type: Opaque
  spec:
    containers:
    - name: $(NAME)
      image: $(IMAGE)
      imagePullPolicy: $(IMAGE_PULL_POLICY)
      env:
      - name: USERNAME
        valueFrom: {secretKeyRef: {name: $(NAME)-$(INSTANCE)-$(SECRET_REF), key: USERNAME}}    
      - name: PASSWORD
        valueFrom: {secretKeyRef: {name: $(NAME)-$(INSTANCE)-$(SECRET_REF), key: PASSWORD}}
      command: ["printenv"]
      args: ["USERNAME"]
parameters:
- name: NAME
  description: Application name
  required: true
  type: string
- name: INSTANCE
  description: >
    Instance ID (used to distinguish between multiple instances (stable, canary, etc.) of the same 
    app within the same namespace)
  value: default
  required: true
  type: string
- name: SECRET_REF
  description: > 
    Unique secret identifier (in can be anything, like a monotonic counter or a SHA-2 of the 
    previous SECRET_REF) (used to distinguish between different versions of the same secret)
  required: true
  type: string  
- name: IMAGE
  description: image (e.g. debian:jessie)
  required: true
  type: string
- name: IMAGE_PULL_POLICY
  description: Image Pull Policy (e.g. IfNotPresent, Always, etc)
  value: IfNotPresent
  required: true
  type: string
```

</details>
<details>
  <summary>&lt;project_dir&gt;/k8s/template.secret.yml</summary>
  
```yml
# snippet:k8s/template.secret.yml
apiVersion: v1
kind: Template
metadata:
  name: template.secret
objects:
- apiVersion: v1
  kind: Secret
  metadata:
    name: $(NAME)-$(INSTANCE)-$(SECRET_REF)
  type: Opaque
  data:
    USERNAME: ""
    PASSWORD: ""
parameters:
- name: NAME
  description: Application name
  required: true
  type: string
- name: INSTANCE
  description: >
    Instance ID (used to distinguish between multiple instances (stable, canary, etc.) of the same 
    app within the same namespace)
  value: default
  required: true
  type: string
- name: SECRET_REF
  description: > 
    Unique secret identifier (in can be anything, like a monotonic counter or a SHA-2 of the 
    previous SECRET_REF) (used to distinguish between different versions of the same secret)
  required: true
  type: string
```

</details>
<details>
  <summary>&lt;project_dir&gt;/k8s/staging.env.yml</summary>
           
```yml
# snippet:k8s/staging.env.yml
NAME: myapp
SECRET_REF: 0
```

</details>
<p><p>

> BTW, all these files (+ `kubetpl`) are included in `shyiko/kubesec-playground` docker image [#playground](#playground).

Let's start by creating a `Secret` and deploying an app.

```sh
# create Secret
kubetpl render k8s/template.secret.yml -i k8s/staging.env.yml | 
  kubesec encrypt -o k8s/staging.secret.enc.yml
kubesec edit -i k8s/staging.secret.enc.yml
kubesec decrypt k8s/staging.secret.enc.yml | kubectl apply -f -

# deploy app
kubetpl render k8s/template.yml -i k8s/staging.env.yml -s IMAGE=debian:jessie | kubectl apply -f -
```

At this point `k8s/staging.secret.enc.yml` should look something like:  

```yml
apiVersion: v1
kind: Secret
metadata:
  name: myapp-default-0
type: Opaque
data:
  USERNAME: TUFkWD1iuKs=.O...=.D...=
  PASSWORD: iOy1nf90+M6FrrEIoymN6cOSUYM=.E...=.q...=
# ...  
```    
> (this is probably a good time to commit `k8s/staging.secret.enc.yml` to the VCS)

Alright, imagine we need to change USERNAME.   

> The general recommendation is to treat `ConfigMap`/`Secret`s as immutable 
(in other words, once `ConfigMap`/`Secret` are in use - they should never (ever) change). 
This is why we are going to generate a new secret instead of `kubesec edit ...`ing the previous one.
Pay attention to `kubesec merge ...` part (it's used to copy the "data" from the previous version of the Secret so that we wouldn't have 
to copy-paste).
 
```sh
# update SECRET_REF
# either open k8s/staging.env.yml in your $EDITOR of choice and make the change manually
# or "Use the Force, Luke" (https://github.com/mikefarah/yaml)
yaml w -i k8s/staging.env.yml \
  SECRET_REF $(cat k8s/staging.env.yml | openssl sha256 | cut -d\  -f2 | cut -c 1-32) 

# update Secret
kubetpl render k8s/template.secret.yml -i k8s/staging.env.yml |
  kubesec merge k8s/staging.secret.enc.yml - -o k8s/staging.secret.enc.yml 
kubesec edit -i k8s/staging.secret.enc.yml # if needed
kubesec decrypt k8s/staging.secret.enc.yml | kubectl apply -f -

# re-deploy app
kubetpl render k8s/template.yml -i k8s/staging.env.yml -s IMAGE=debian:jessie | kubectl apply -f -
```

## Encryption Protocol

- "data" values are encrypted with AES-GCM 
(each value is padded to a block-size (48 bytes by default) and then encrypted using a shared (resource-unique, randomly generated) 256-bit DEK & a 96-bit random IV).
- DEK is encrypted (and signed in case of PGP) with `--key`(s) before being stored in a Secret as `# kubesec:<key type>:<key id>:...` (one entry for each `--key`).

In addition to the above, kubesec also generates MAC (AES-GMAC, with AAD constructed from both the "data" and the `--key`(s)). If MAC is missing or invalid - 
decryption will fail (`kubesec edit -i --recompute-mac <file>` can be used to recompute MAC when necessary (e.g. after `git merge`)).  

## Reporting Security Issues

Please reach me at https://keybase.io/shyiko. 

## Development

> PREREQUISITE: [go1.8](https://golang.org/dl/)+.

```sh
git clone https://github.com/shyiko/kubesec $GOPATH/src/github.com/shyiko/kubesec 
cd $GOPATH/src/github.com/shyiko/kubesec
make fetch

go run kubesec.go
```

## Legal

All code, unless specified otherwise, is licensed under the [MIT](https://opensource.org/licenses/MIT) license.  
Copyright (c) 2017 Stanley Shyiko.
