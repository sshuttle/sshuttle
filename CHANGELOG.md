# Changelog

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
