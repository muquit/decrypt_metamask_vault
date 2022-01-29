#!/usr/bin/env python3

########################################################################
#  Decrypt Metamask's encrypted vault
#  muquit@muquit.com Jan-26-2022 
########################################################################

import argparse
import logging
import sys
import json
import base64
import os, binascii
from hashlib import pbkdf2_hmac
from os.path import exists
from Crypto.Cipher import AES
from getpass import getpass

if __name__ == "__main__":
    log_format = "%(levelname)s %(asctime)s - %(message)s"
    logger = logging.getLogger(__name__)
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        stream=sys.stdout)

    parser = argparse.ArgumentParser(description="Decrypt Metamask Vault")
    parser.add_argument('-f',
            help="Path of Metamask vault JSON file",
            required=True)
    args = parser.parse_args()
    json_file = args.f

    if exists(json_file) != True:
        print(f"Error: file {json_file} does not exist")
        exit(1)

    f = open(json_file)
    j = json.load(f)
    f.close()

    # prompt for Metamask password
    password = getpass("Enter Metamask Password: ")

    # make key from password, Metamask uses iter=10,000, key is 
    # 32 bytes long
    saltBytes = base64.b64decode(j['salt'])
    password = password.encode("utf8")
    key = pbkdf2_hmac("sha256", password, saltBytes, 10000,32)

    # decrypt data with the generated key. AES-256 GCM mode
    ivBytes = base64.b64decode(j['iv'])
    ivLen = len(ivBytes)
    dataBytes = base64.b64decode(j['data'])
    aesgcm = AES.new(key, AES.MODE_GCM, ivBytes)
    plainText = aesgcm.decrypt(dataBytes)
    print(f"{plainText}")