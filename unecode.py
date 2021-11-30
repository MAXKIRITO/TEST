from Crypto.Cipher import AES
from Crypto import Random
from PIL import Image
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import pytesseract
import base64

pytesseract.pytesseract.tesseract_cmd = 'C:\Program Files\Tesseract-OCR\\tesseract.exe'

# 讀取 RSA 私鑰
privateKey = RSA.import_key(open("private.pem").read())

# 從檔案讀取加密資料
with open("encrypted_data", "rb") as f:
    encSessionKey = f.read(privateKey.size_in_bytes())
    nonce = f.read(16)
    tag = f.read(16)
    ciphertext = f.read(-1)

# 以 RSA 金鑰解密 Session 金鑰
cipherRSA = PKCS1_OAEP.new(privateKey)
sessionKey = cipherRSA.decrypt(encSessionKey)

# 以 AES Session 金鑰解密資料
cipherAES = AES.new(sessionKey, AES.MODE_EAX, nonce)
data = cipherAES.decrypt_and_verify(ciphertext, tag)

# 輸出解密後的資料
img = base64.b64decode(data)
output_file = open("output.jpg", "wb+")
output_file.write(img)
output_file.close()








