# Changelog

## [1.3.3](https://github.com/sshuttle/sshuttle/compare/v1.3.2...v1.3.3) (2026-02-13)


### Bug Fixes

* Correct PYTHONPATH for --sudoers-no-modify ([#1084](https://github.com/sshuttle/sshuttle/issues/1084)) ([0284a49](https://github.com/sshuttle/sshuttle/commit/0284a49254d410d01b422c1a7ddc88a72572b263))
* route PRINT -4 to_ascii [windows] ([cb9c0f3](https://github.com/sshuttle/sshuttle/commit/cb9c0f3548c0af9cf224e069aca596c2f1308c22))

## [1.3.2](https://github.com/sshuttle/sshuttle/compare/v1.3.1...v1.3.2) (2025-08-08)


### Bug Fixes

* improve broken pipe (EPIPE) error handling in socket operations ([47c5afe](https://github.com/sshuttle/sshuttle/commit/47c5afe3f5e65d84894b617803e3272a0987f641))
* improve broken pipe (EPIPE) error handling in socket operations ([514847e](https://github.com/sshuttle/sshuttle/commit/514847e7d86f65be7315f390e20987a9352840ca))
* Updates sudoers config according to executable ([934fac9](https://github.com/sshuttle/sshuttle/commit/934fac9d6c0f86223e3e7120148d346d9b20c9d0))

## [1.3.1](https://github.com/sshuttle/sshuttle/compare/v1.3.0...v1.3.1) (2025-03-25)


### Bug Fixes

* add pycodestyle config ([5942376](https://github.com/sshuttle/sshuttle/commit/5942376090395d0a8dfe38fe012a519268199341))
* add python lint tools ([ae3c022](https://github.com/sshuttle/sshuttle/commit/ae3c022d1d67de92f1c4712d06eb8ae76c970624))
* correct bad version number at runtime ([7b66253](https://github.com/sshuttle/sshuttle/commit/7b662536ba92d724ed8f86a32a21282fea66047c))
* Restore "nft" method ([375810a](https://github.com/sshuttle/sshuttle/commit/375810a9a8910a51db22c9fe4c0658c39b16c9e7))

## [1.3.0](https://github.com/sshuttle/sshuttle/compare/v1.2.0...v1.3.0) (2025-02-23)


### Features

* switch to a network namespace on Linux ([8a123d9](https://github.com/sshuttle/sshuttle/commit/8a123d9762b84f168a8ca8c75f73e590954e122d))


### Bug Fixes

* prevent UnicodeDecodeError parsing iptables rule with comments ([cbe3d1e](https://github.com/sshuttle/sshuttle/commit/cbe3d1e402cac9d3fbc818fe0cb8a87be2e94348))
* remove temp build hack ([1f5e6ce](https://github.com/sshuttle/sshuttle/commit/1f5e6cea703db33761fb1c3f999b9624cf3bc7ad))
* support ':' sign in password ([7fa927e](https://github.com/sshuttle/sshuttle/commit/7fa927ef8ceea6b1b2848ca433b8b3e3b63f0509))


### Documentation

* replace nix-env with nix-shell ([340ccc7](https://github.com/sshuttle/sshuttle/commit/340ccc705ebd9499f14f799fcef0b5d2a8055fb4))
* update installation instructions ([a2d405a](https://github.com/sshuttle/sshuttle/commit/a2d405a6a7f9d1a301311a109f8411f2fe8deb37))

## [1.2.0](https://github.com/sshuttle/sshuttle/compare/v1.1.2...v1.2.0) (2025-02-07)


### Features

* Add release-please to build workflow ([d910b64](https://github.com/sshuttle/sshuttle/commit/d910b64be77fd7ef2a5f169b780bfda95e67318d))


### Bug Fixes

* Add support for Python 3.11 and Python 3.11 ([a3396a4](https://github.com/sshuttle/sshuttle/commit/a3396a443df14d3bafc3d25909d9221aa182b8fc))
* bad file descriptor error in windows, fix pytest errors ([d4d0fa9](https://github.com/sshuttle/sshuttle/commit/d4d0fa945d50606360aa7c5f026a0f190b026c68))
* drop Python 3.8 support ([1084c0f](https://github.com/sshuttle/sshuttle/commit/1084c0f2458c1595b00963b3bd54bd667e4cfc9f))
* ensure poetry works for Python 3.9 ([693ee40](https://github.com/sshuttle/sshuttle/commit/693ee40c485c70f353326eb0e8f721f984850f5c))
* fix broken workflow_dispatch CI rule ([4b6f7c6](https://github.com/sshuttle/sshuttle/commit/4b6f7c6a656a752552295863092d3b8af0b42b31))
* Remove more references to legacy Python versions ([339b522](https://github.com/sshuttle/sshuttle/commit/339b5221bc33254329f79f2374f6114be6f30aed))
* replace requirements.txt files with poetry ([85dc319](https://github.com/sshuttle/sshuttle/commit/85dc3199a332f9f9f0e4c6037c883a8f88dc09ca))
* replace requirements.txt files with poetry (2) ([d08f78a](https://github.com/sshuttle/sshuttle/commit/d08f78a2d9777951d7e18f6eaebbcdd279d7683a))
* replace requirements.txt files with poetry (3) ([62da705](https://github.com/sshuttle/sshuttle/commit/62da70510e8a1f93e8b38870fdebdbace965cd8e))
* replace requirements.txt files with poetry (4) ([9bcedf1](https://github.com/sshuttle/sshuttle/commit/9bcedf19049e5b3a8ae26818299cc518ec03a926))
* update nix flake to fix problems ([cda60a5](https://github.com/sshuttle/sshuttle/commit/cda60a52331c7102cff892b9b77c8321e276680a))
* use Python &gt;= 3.10 for docs ([bf29464](https://github.com/sshuttle/sshuttle/commit/bf294643e283cef9fb285d44e307e958686caf46))
