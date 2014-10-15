#!/usr/bin/env python
# -*- coding: utf-8 -*-

# http://isombyt.me/android-java-reversed-engineering-3

import requests
from Crypto.Cipher import PKCS1_v1_5, DES3
from Crypto.PublicKey import RSA
import json
import hashlib

randKey = "A" * 32


def rsaEncrypt(data, key):
    cipher = PKCS1_v1_5.new(RSA.importKey(key))
    return cipher.encrypt(data)


_pad_ = lambda s: s + (32 - len(s) % 32) * chr(32 - len(s) % 32)

_unpad_ = lambda s: s[0:-ord(s[-1])]


def desDecrypt(data, key):
    cipher = DES3.new(randKey[:24], DES3.MODE_ECB)
    return _unpad_(cipher.decrypt(data))


def desEncrypt(data, key):
    cipher = DES3.new(randKey[:24], DES3.MODE_ECB)
    return cipher.encrypt(_pad_(data))

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

data = json.loads(desDecrypt(handshakeRespJson["data"].decode("base64"), randKey))
print data
headers["X-TOKEN"] = data["token"]

deviceid = "A" * 16

phone = "+86-手机号"

password = "密码"

signStr = "deviceid=%s&password=%s&phone=%s" % (deviceid, password, phone)
params = "phone=%s&password=%s&deviceid=%s" % (phone, password, deviceid)

data = desEncrypt(params, randKey).encode("base64")

headers["X-Signature"] = hashlib.md5((signStr+randKey).lower()).hexdigest().upper()

loginResp = requests.post(
    "http://api.mygm.sdo.com/v1/account/login",
    data=data,
    headers=headers
)

loginRespJson = loginResp.json()

print desDecrypt(loginRespJson["data"].decode("base64"), randKey)