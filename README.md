# kubesec ![Latest Version](https://img.shields.io/badge/latest-WIP-blue.svg) [![Build Status](https://travis-ci.org/shyiko/kubesec.svg?branch=master)](https://travis-ci.org/shyiko/jabba)

Secure secret management for Kubernetes.
  
In short, it allows you to encrypt [Secret](https://kubernetes.io/docs/concepts/configuration/secret/)s so that they could be stored in VCS along 
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
(`kubesec`'ve drawn a lot of inspiration from it). 

## Installation

#### macOS / Linux

```sh
curl -sSL https://github.com/shyiko/kubesec/releases/download/0.1.0/kubesec-0.1.0-$(
    bash -c '[ $OSTYPE = darwin* ] && echo darwin || echo linux'
  )-amd64 > kubesec && chmod a+x kubesec
    
# verify PGP signature (optional but RECOMMENDED)
curl -sSL https://github.com/shyiko/kubesec/releases/download/0.1.0/kubesec-0.1.0-$(
    bash -c '[ $OSTYPE = darwin* ] && echo darwin || echo linux'
  ).asc > kubesec.asc
curl https://keybase.io/shyiko/pgp_keys.asc | gpg --import
gpg --verify kubesec.asc
```  

#### Windows

Download binary from the "[release(s)](https://github.com/shyiko/kubesec/releases)" page.

## Usage

> [gpg](https://gnupg.org/) (tested on 2.1+) **must** be available on the PATH.  

```sh
# encrypt a Secret
kubesec encrypt secret.yml

# same as above but output is written back to secret.yml (instead of stdout)
kubesec encrypt -i secret.yml

# encrypt with specific key (you can specify multiple --key|s if you want)
kubesec encrypt --key=6206C32E111611688694CF5530BDA87E3E71C268 secret.yml

# add ...D89 key & drop ...310 key (leave all other keys untouched)
kubesec encrypt --key=+160A7A9CF46221A56B06AD64461A804F2609FD89 \
  --key=-6206C32E111611688694CF5530BDA87E3E71C268 secret.yml
# NOTE: removal of a key will automatically result in encryption key rotation
# you will also need to change all the secrets as whoever you removed from the chain of trust might 
# still have access to the previous version of a file   

# encrypt content of stdin
cat secret.yml | kubesec encrypt -

# decrypt a Secret 
# (usually combined with kubectl (`kubesec decrypt secret.yml | kubectl apply -f -`))
kubesec decrypt secret.yml 

# open decrypted Secret in $EDITOR (it will be automatically re-encrypted upon save)
kubesec edit -i secret.yml

# show information about the Secret (who has access to the "data", last modification date, etc)
kubesec introspect secret.yml
```

> `-` can be used anywhere (where a file is expected) to reference `stdin`.  
> (for more information see `kubesec --help`)

## Playground

If you have `docker` installed you don't need to download `kubesec` binary just to try it out.  
Instead, launch a container and start playing: 

```sh
docker run -it --rm shyiko/kubesec-playground:latest /bin/bash
$ kubesec encode secret.yml
```

> `shyiko/kubesec-playground` image contains `gpg` 2.1+, kubesec, vim (as a default $EDITOR) and 
  secret PGP key of Jean-Luc Picard (PGP fingerprint - 6206C32E111611688694CF5530BDA87E3E71C268). 

> Dockerfile [is included within this repo](kubesec-playground.dockerfile).

## Example(s)
 
#### #1 (basic)

```sh
echo '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"app-stable-0"},"type":"Opaque",
  "data":{"KEY":"dmFsdWUK","ANOTHER_KEY":"YW5vdGhlcl92YWx1ZQo="}}' | 
  kubesec encrypt > secret.yml
kubesec edit -i secret.yml  
kubesec decrypt secret.yml | kubectl apply -f - 
```

#### #2 (client-side templating)

> To keep things simple, we'll use [ktmpl](https://github.com/InQuicker/ktmpl) (template format is described in [this design proposal](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/templates.md)).  
You are free to choose a different one (e.g. [helm-template](https://github.com/technosophos/helm-template)). 

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
  parameterType: string
- name: INSTANCE
  description: >
    Instance ID (used to distinguish between multiple instances (stable, canary, etc.) of the same 
    app within the same namespace)
  value: default
  required: true
  parameterType: string
- name: SECRET_REF
  description: > 
    Unique secret identifier (in can be anything, like a monotonic counter or a SHA-2 of the 
    previous SECRET_REF) (used to distinguish between different versions of the same secret)
  required: true
  parameterType: string  
- name: IMAGE
  description: image (e.g. debian:jessie)
  required: true
  parameterType: string
- name: IMAGE_PULL_POLICY
  description: Image Pull Policy (e.g. IfNotPresent, Always, etc)
  value: IfNotPresent
  required: true
  parameterType: string
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
  parameterType: string
- name: INSTANCE
  description: >
    Instance ID (used to distinguish between multiple instances (stable, canary, etc.) of the same 
    app within the same namespace)
  value: default
  required: true
  parameterType: string
- name: SECRET_REF
  description: > 
    Unique secret identifier (in can be anything, like a monotonic counter or a SHA-2 of the 
    previous SECRET_REF) (used to distinguish between different versions of the same secret)
  required: true
  parameterType: string
```

</details>
<details>
  <summary>&lt;project_dir&gt;/k8s/deployment/minikube.yml (context-specific configuration; you'll probably have other files like 
           &lt;project_dir&gt;/k8s/deployment/gke.yml, &lt;project_dir&gt;/k8s/deployment/gke-staging.yml, etc)</summary>
           
```yml
# snippet:k8s/deployment/minikube.yml
NAME: myapp
SECRET_REF: "0"
```

</details>

> BTW, all these files (+ `ktmpl`) are included in `shyiko/kubesec-playground` docker image [#playground](#playground).

Let's start by creating a `Secret` and deploying an app.

```sh
# create Secret
ktmpl k8s/template.secret.yml -f k8s/deployment/minikube.yml | 
  kubesec encrypt -o k8s/deployment/minikube.secret.yml
kubesec edit -i k8s/deployment/minikube.secret.yml
kubesec decrypt k8s/deployment/minikube.secret.yml | kubectl apply -f -

# deploy app
ktmpl k8s/template.yml -f k8s/deployment/minikube.yml -p IMAGE debian:jessie | kubectl apply -f -
```

At this point `k8s/deployment/minikube.secret.yml` should look something like:  

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
> (this is probably a good time to commit `k8s/deployment/minikube.secret.yml` to the VCS)

Alright, imagine we need to change USERNAME.   

> The general recommendation is to treat `ConfigMap`/`Secret`s as immutable 
(in other words, once `ConfigMap`/`Secret` are in use - they should never (ever) change). 
This is why we are going to generate a new secret instead of `kubesec edit ...`ing the previous one.
Pay attention to `kubesec merge ...` part (it's used to copy the "data" from the previous version of the Secret so that we wouldn't have 
to copy-paste).
 
```sh
# update SECRET_REF
# either open k8s/deployment/minikube.yml in your $EDITOR of choice and make the change manually
# or "Use the Force, Luke" (https://github.com/mikefarah/yaml)
yaml w -i k8s/deployment/minikube.yml \
  SECRET_REF $(cat k8s/deployment/minikube.yml | openssl sha256 | cut -d\  -f2 | cut -c 1-32) 

# update Secret
ktmpl k8s/template.secret.yml -f k8s/deployment/minikube.yml |
  kubesec merge k8s/deployment/minikube.secret.yml - -o k8s/deployment/minikube.secret.yml 
kubesec edit -i k8s/deployment/minikube.secret.yml # if needed
kubesec decrypt k8s/deployment/minikube.secret.yml | kubectl apply -f -

# re-deploy app
ktmpl k8s/template.yml -f k8s/deployment/minikube.yml -p IMAGE debian:jessie | kubectl apply -f -
```

## Encryption Protocol

- "data" values are encrypted with AES-GCM 
(each value is padded to a block-size (32 bytes by default) and then encrypted using a shared (resource-unique, randomly generated) 256-bit DEK & a 96-bit random IV).
- DEK is encrypted with public PGP `--key`(s) & signed with private PGP key (from the same set) before being stored in a Secret as `# kubesec:pgp:...`.

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
