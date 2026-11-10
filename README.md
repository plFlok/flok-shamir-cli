# Flok Shamir CLI

A single Python script for splitting and recovering secrets in the
[flok.codes](https://flok.codes/shamir_secret_sharing) share format. It
generates FSS2 shares and recovers both FSS2 and legacy FSS1 shares. You can
use FSS2 shares from the CLI in the browser tool and vice versa. The CLI works
offline.

## Installation

Use Python 3.9.2 or newer. FSS2 encoding and recovery use only the standard
library. Install [`cryptography`](https://cryptography.io/en/latest/hazmat/primitives/aead/)
to recover legacy FSS1 shares.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

## Split a secret

```sh
umask 077
.venv/bin/python shamir.py encode --shares 5 --threshold 3 --input secret.txt > shares.json
```

`encode` writes JSON to stdout. Each `keyN` field contains one complete Base64
share. The `powered_by` field is always `"https://flok.codes"`. The command above
produces `key1` through `key5` and `powered_by`.

| Argument | Description |
| --- | --- |
| `-n`, `--shares N` | Number of shares to generate, from 2 to 20. Default is 8. |
| `-t`, `--threshold K` | Number of distinct shares needed to recover the secret, from 2 to N. Default is 5. |
| `-i`, `--input FILE` | A UTF-8 text file containing 1 to 4096 bytes. Reads stdin until EOF when omitted. |

The script preserves whitespace, byte order marks, and line endings. Treat
`shares.json` like the original secret because it holds every share. Give
each holder only their own `keyN` value.

## Recover a secret

```sh
.venv/bin/python shamir.py decode --input shares.json
cat share-1.txt share-3.txt share-5.txt | .venv/bin/python shamir.py decode
```

`decode -i FILE` accepts the JSON from `encode` or one Base64 share per line,
including text files downloaded from the site. It reads stdin when `-i` is
omitted. A JSON input can contain a subset of the original `keyN` fields in
any order. `powered_by` is optional. Use shares from the same set. Each share
records the recovery threshold.

The original UTF-8 bytes go to stdout, with no extra newline. Errors go to
stderr and cause a nonzero exit status. If a share is stored as a QR code,
scan it first and copy the Base64 text or the `share` value from the scanned
JSON.

Run `python3 shamir.py --help`, `python3 shamir.py encode --help`, or
`python3 shamir.py decode --help` for command-line help.

## Prepare for offline recovery

Keep a copy of `shamir.py` and try recovering a test secret. For FSS1, install
the dependency ahead of time or save wheels for the Python version and
platform you will use for recovery.

```sh
.venv/bin/python -m pip download --only-binary=:all: -r requirements.txt -d wheelhouse
.venv/bin/python -m pip install --no-index --find-links=wheelhouse -r requirements.txt
```

The CLI matches the site's share format, including GF(256) arithmetic, share
coordinates, checksums, and verification of the recovered secret. The browser
tool uses [shamir-secret-sharing](https://github.com/privy-io/shamir-secret-sharing).
The Python implementation has not undergone an independent security audit.

## License

[MIT](LICENSE).
