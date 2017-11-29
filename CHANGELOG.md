# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

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

[0.4.1]: https://github.com/shyiko/kubesec/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/shyiko/kubesec/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/shyiko/kubesec/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/shyiko/kubesec/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/shyiko/kubesec/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/shyiko/kubesec/compare/0.1.0...0.1.1
