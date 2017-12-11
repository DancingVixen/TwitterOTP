#!/usr/bin/python3

'''
Program Name: CryptBot.py
Writen By:    NotPike
Function:     One Time Pad for Twitter

One Time Pad logic based off of jailuthra's code
https://github.com/jailuthra
'''

#Import
import tweepy
import argparse
import binascii
import itertools
import base64
import os


#Twitter Creds
twitterName = ""
consumerKey = ""
consumerSecret = ""
accessToken = ""
accessTokenSecret = ""

#Twiter Auth
auth = tweepy.OAuthHandler(consumerKey, consumerSecret)
auth.set_access_token(accessToken, accessTokenSecret)
api = tweepy.API(auth)


def main():
    #Command Arguments
    parser = argparse.ArgumentParser(description="Crypt Twitter Bot by NotPike")
    parser.add_argument('-e', dest="encrypt",help='Send an encrypted message')
    parser.add_argument('-d', dest="decrypt",help='Decrypt a message')
    parser.add_argument('-k', dest="key",help='Key for Encryption and Decrypt')
    arguments = parser.parse_args()

    #Dem Arument Logic
    if(arguments.encrypt):
        msg = arguments.encrypt
        tweet(msg)
    elif(arguments.decrypt):
        msg = arguments.decrypt
        key = arguments.key
        print(oneTimePadDecrypt(msg,key))

def oneTimePadEncrypt(msg):
    key = keyGen(len(msg))
    print("Key: " + key)
    cipher = xor(msg, key)
    cipher = (binascii.hexlify(cipher.encode())).decode()
    return cipher

def oneTimePadDecrypt(cipher,key):
    cipher = (binascii.unhexlify(cipher.encode())).decode()
    msg = xor(cipher, key)
    return msg

def xor(a,b):
    xorred = ''.join([chr(ord(x)^ord(y)) for x, y in zip(a, itertools.cycle(b))])
    return xorred

def keyGen(msgLength):
    key = base64.b64encode(os.urandom(msgLength)).decode('utf-8')
    return key

def tweet(msg):
    cryptMsg = oneTimePadEncrypt(msg)

    #Checks to see if encrypted msg is larger then 240 chr
    if(len(cryptMsg) > 240):
        print("Message is too long")
    else:
        print("Message: " + cryptMsg)
        api.update_status(cryptMsg)

if __name__ == "__main__":
    main()
      
