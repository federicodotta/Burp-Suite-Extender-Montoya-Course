import flask
from flask import request
import base64
from Crypto import Random
from Crypto.Cipher import AES

app = flask.Flask(__name__)

# Encryption stuff from:
# https://stackoverflow.com/questions/12524994/encrypt-and-decrypt-using-pycrypto-aes-256

bs = AES.block_size
key = bytes.fromhex("eeb27c55483270a92682dab01b85fdea")
iv = bytes.fromhex("ecbc1312cfdc2a0e1027b1eaf577dce8")

def encrypt(raw):
    raw = _pad(raw)    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(cipher.encrypt(raw.encode()))

def decrypt(enc):
    enc = base64.b64decode(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _unpad(cipher.decrypt(enc)).decode('utf-8')

def _pad(s):
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

def _unpad(s):
    return s[:-ord(s[len(s)-1:])]


@app.route('/', methods=['POST'])
def handle_request():

    encrypted_body = request.get_data()
    decrypted_body = decrypt(encrypted_body)

    response = "Your request was: \"" + decrypted_body + "\""
    encrypted_response = encrypt(response)

    return encrypted_response
    

app.run(host="127.0.0.1", port=5000, debug=True)