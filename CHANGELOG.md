# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2018-04-14

### Added
- Ability to specify `--annotation/-a`s and `--label/-l`s when `create`ing/`patch`ing secrets. e.g.

    ```sh
    $ kubesec create secret-name \
        -a origin=https://... \
        -a version=0.1.0+$(date -u +%Y%m%dT%H%M%SZ).$(git rev-parse --short HEAD) \
        -l release=canary
        -d k=v
    
    apiVersion: v1
    data: 
       k: PYsYSsk...
    kind: Secret
    metadata:
      annotations:
        origin: https://...
        version: 0.1.0+20180415T040932Z.a9070e4
      labels:
        release: canary
      name: secret-name
    type: Opaque
    # kubesec:v:3
    # ...
    ```  

- `kubesec encrypt secret.yml --parent=path/to/secret.enc.yml`  
(encrypts secret.yml using keys & DEK (preserving IVs when safe) from secret.enc.yml).  
  
    Useful in "decrypt, modify, re-encrypt-preserving-DEK" scenarios.   

- `-x` shorthand for `--cleartext`.
- A guard against `failed to base64-decode <key>`  
("data" values are now checked to be base64-encoded before being encrypted). 

### Deprecated
- `kubesec merge`.

## [0.6.2] - 2018-04-12

### Fixed
- `unknown shorthand flag: 'i' in -i` / `unknown flag: --in-place`   
(in case of `kubesec patch -i/--in-place`) 

## [0.6.1] - 2018-04-06

### Fixed
- `invalid argument "k=\"" for "-d, --data" flag: line 1, column 2: bare " in non-quoted-field`  
(`"` inside `-d/--data` value handling)

## [0.6.0] - 2018-03-01

### Added
- `--metadata namespace=...` support ([#5](https://github.com/shyiko/kubesec/pull/5)).

## [0.5.0] - 2018-02-03

### Added
- `kubesec create` for Secret bootstraping (from a set of key=value pairs / files): 
  
    ```sh
    $ kubesec create secret-name \
        --data key=value \
        --data file:pki/ca.crt \
        --data file:key.pem=pki/private/server.key
    ```
(`kubesec create --help` for more).
- `kubesec patch` for batch Secret editing: 
  
    ```sh
    $ kubesec patch secret.enc.yml --data key=value --data file:ta.key
    ```     
(`kubesec patch --help` for more). 
- [<kbd>Tab</kbd> completion](https://github.com/shyiko/kubesec#tab-completion) (for bash and zsh).

## [0.4.2] - 2017-12-27

### Fixed
- Error reported by `kubesec decrypt --template=...` when data cannot be decrypted.   

## [0.4.1] - 2017-11-29

### Fixed
- `--template` rendering (html-significant characters are no longer escaped).  

## [0.4.0] - 2017-11-29

### Added
- kubesec decrypt `--template <go-template-string>` option. e.g.

    ```sh
    $ kubesec decrypt --cleartext \
        --template=$'USERNAME={{ .data.USERNAME }}\nPASSWORD={{ .data.PASSWORD }}' \
        k8s/staging.secret.enc.yml > .env
    
    $ cat .env
    
    USERNAME=username
    PASSWORD=password    
    ```  

## [0.3.1] - 2017-09-29

### Fixed
- MAC mismatch warning when `kubesec edit`ing unencrypted Secret.
- List of keys reported when `kubesec edit`ing with `--key` option provided.  

## [0.3.0] - 2017-09-16

### Added
- MAC (AES-GMAC, covering both "data" and `--key`(s)).
- `--cleartext` flag (available for `encrypt` & `decrypt` commands). e.g.

    ```sh
    $ kubesec decrypt k8s/staging.secret.enc.yml
    
    data:
      key: dmFsdWU= 
    ...
    
    $ kubesec decrypt --cleartext k8s/staging.secret.enc.yml
    
    data:
      key: value
    ...
    ```

### Fixed
- `edit --rotate` having no effect unless "data" is modified. 

### Changed
- "" (empty string) encryption to produce an opaque value.

## [0.2.0] - 2017-08-29

### Added
- [Google Cloud KMS](https://cloud.google.com/kms/) and [AWS KMS](https://aws.amazon.com/kms/) backends.
- `--key=pgp:default` alias.
- Ability to specify a different set of keys for data encryption when `kubesec edit`ing (using `--key=...`). 

## [0.1.1] - 2017-08-15

### Fixed
- `gpg` lookup on macOS ([#2](https://github.com/shyiko/kubesec/issues/2))

## 0.1.0 - 2017-08-11

[0.7.0]: https://github.com/shyiko/kubesec/compare/0.6.2...0.7.0
[0.6.2]: https://github.com/shyiko/kubesec/compare/0.6.1...0.6.2
[0.6.1]: https://github.com/shyiko/kubesec/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/shyiko/kubesec/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/shyiko/kubesec/compare/0.4.2...0.5.0
[0.4.2]: https://github.com/shyiko/kubesec/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/shyiko/kubesec/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/shyiko/kubesec/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/shyiko/kubesec/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/shyiko/kubesec/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/shyiko/kubesec/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/shyiko/kubesec/compare/0.1.0...0.1.1
