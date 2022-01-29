# Introduction

I wanted to find out how Metamask keeps the vault data encrypted. Turns out it uses [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) to stretch the password to a key with 10,000 iteration to generate a 32 byte key for AES-256 GCM. It uses 16 bytes iv instead of usual 12 bytes.

Look at this page https://metamask.zendesk.com/hc/en-us/articles/360036464651-How-to-recover-a-Secret-Recovery-Phrase to see in what circumstances you might need to decrypt the vault and how to extract the vault JSON file.

# golang

**No binaries will be supplied** as it exposes your recovery passphrase. Please look at main.go carefully and then compile it yourself. To compile, install go from https://go.dev/ first. Then type:

```
go build -o decrypt_metamask_vault
```

```
./decrypt_metamask_vault -h
Usage of ./decrypt_metamask_vault:
  -f string
    	Path of Metamask vault JSON file
```

# Python

```
python3 -m venv ./python3-venv
source ./python3-venv/bin/activate
pip install -r requirements.txt
```

```
./decrypt_metamask_vault.py -h
usage: decrypt_metamask_vault.py [-h] -f F

Decrypt Metamask Vault

optional arguments:
  -h, --help  show this help message and exit
  -f F        Path of Metamask vault JSON file
```

# ruby

It's broken at this time.

ruby version uses OpenSSL and it insists on using 12 bytes iv for AES-256 GCM. If iv length is specified, decryption fails. If any of you can make it work, please send a pull request.
