from Crypto.Cipher import AES
from Crypto import Random
from PIL import Image
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import pytesseract
import base64   

pytesseract.pytesseract.tesseract_cmd = 'C:\Program Files\Tesseract-OCR\\tesseract.exe'

input_file = open("input.jpg")
img = Image.open('input.jpg')
input_data = base64.b64encode(open('input.jpg',"rb").read())
input_file.close()

publicKey = RSA.import_key(open("public.pem").read())
sessionKey = get_random_bytes(16)
cipherRSA = PKCS1_OAEP.new(publicKey)
encSessionKey = cipherRSA.encrypt(sessionKey)
cipherAES = AES.new(sessionKey, AES.MODE_EAX)
ciphertext, tag = cipherAES.encrypt_and_digest(input_data)

with open("encrypted_data", "wb") as f:
    f.write(encSessionKey)
    f.write(cipherAES.nonce)
    f.write(tag)
    f.write(ciphertext)

