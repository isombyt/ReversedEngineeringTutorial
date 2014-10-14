#!/usr/bin/env python
# -*- coding: utf-8 -*-

# http://isombyt.me/android-java-reversed-engineering-2

import requests
from Crypto.Cipher import PKCS1_v1_5, DES3
from Crypto.PublicKey import RSA


randKey = "A" * 32


def rsaEncrypt(data, key):
    cipher = PKCS1_v1_5.new(RSA.importKey(key))
    return cipher.encrypt(data)


def desDecrypt(data, key):
    cipher = DES3.new(randKey[:24], DES3.MODE_ECB)
    return cipher.decrypt(data)

headers = {
    "Charset": "UTF-8",
    "X-APP-ID": "791000035",
    "X-Channel": "GG1003",
    "X-TOKEN": "",
    "X-Signature": "",
    "User-Agent": "COS 1.0beta",
}

pubkeyResp = requests.post(
    "http://api.mygm.sdo.com/v1/basic/publickey",
    headers=headers
)

pubkeyRespJson = pubkeyResp.json()
print pubkeyRespJson
rsaKey = pubkeyRespJson["data"]["key"].decode("base64")

params = "randkey=%s" % randKey
data = rsaEncrypt(params, rsaKey).encode("base64")

handshakeResp = requests.post(
    "http://api.mygm.sdo.com/v1/basic/handshake",
    data=data,
    headers=headers
)
handshakeRespJson = handshakeResp.json()
print handshakeRespJson

print desDecrypt(handshakeRespJson["data"].decode("base64"), randKey)
