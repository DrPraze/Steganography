"""Steganography code, feel free to use, consider reading throught the code before use, you can use 
it with from encrypt_kit import * and use the method() of your choice."""

import hashlib, os, codecs
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from PIL import Image, ImageDraw

#WARNING:If you want the image to be readable when you use any of the steganography encryptions make sure you use the right steganography
#tool that is the "steganography method", the other ones, "encrypt_to_image" and "decrypt_to_text" would damage the files, that is the image
#would not be viewable 

def encrypt(text, password):
    salt = get_random_bytes(AES.block_size)

    key = hashlib.scrypt(password.encode(), salt=salt, n=2**24, r=8, p=1, dklen=32)
    cipher_config = AES.new(key, AES.MODE_GCM)

    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

def decrypt(enc_dict, password):
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted

def encrypt_to_image(text_, filename):
    text = bytes(text_, 'utf-8')
    with open(filename, 'wb') as img:
        img.write(text)
        img.close
    return filename

def decrypt_to_text(filename):
    with open(filename, 'rb') as img_:
        text = img_.read()
        text = codecs.decode(text, 'utf-8')
        print(text)
        return text

#:::::::::::::::::::::::::::the steganography region:::::::::::::::::::::::::::::::::
def genData(data):
    newd = [format(ord(i), '08b') for i in data]
    return newd

def modPix(pix, data):
    datalist = genData(data)
    data_length = len(datalist)
    imdata = iter(pix)

    for i in range(data_length):
        #3 pixels at a time
        pix = [value for value in imdata.__next__()[:3] +
                                imdata.__next__()[:3] +
                                imdata.__next__()[:3]]


        for j in range(0, 8):
            if (datalist[i][j] == '0' and pix[j]% 2 != 0):
                pix[j] -= 1

            elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                if(pix[j] != 0):
                    pix[j] -= 1
                else:
                    pix[j] += 1
                # pix[j] -= 1

        # Eighth pixel of every set tells whether to stop or continue reading.
        # 0 means keep reading; 1 means the message is finished encrypting.
        if (i == data_length - 1):
            if (pix[-1] % 2 == 0):
                if(pix[-1] != 0):
                    pix[-1] -= 1
                else:
                    pix[-1] += 1
        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1

        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]

def encode_enc(newimg, data):
    w = newimg.size[0]
    (x, y) = (0, 0)

    for pixel in modPix(newimg.getdata(), data):

        # Putting modified pixels in the new image
        newimg.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0
            y += 1
        else:
            x += 1

# Encode data into image
def encode(_image_, data_, output):
    #_image_ is the data to be encrypted, the data_ is the message to be encrypted and the output is the output image name, 
    #the names of images should be with their extensions
    img = _image_
    image = Image.open(_image_, 'r')

    data = data_
    if (len(data) == 0):
        raise ValueError('Data is empty')
    newimg = image.copy()
    encode_enc(newimg, data)

    new_img_name = output
    newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))

# Decode the data in the image
def decode(_image_, ):
    img = _image_
    image = Image.open(img, 'r')

    data = ''
    imgdata = iter(image.getdata())

    while (True):
        pixels = [value for value in imgdata.__next__()[:3] +
                                imgdata.__next__()[:3] +
                                imgdata.__next__()[:3]]

        binstr = ''
        for i in pixels[:8]:
            if (i % 2 == 0):
                binstr += '0'
            else:
                binstr += '1'
        data += chr(int(binstr, 2))
        if (pixels[-1] % 2 != 0):
            return data

# Main Function
def main(option, image, data, output):
    #option only 
    if (option == 1):
        encode(image, data, output)
    elif (option == 2):
        print("Decoded Word : " + decode(image))
    else:
        raise Exception("Incorrect value for option, should be \n('1'. for encrypting), \n('2'. for decrypting)")


#:::::::::::::::::::::::::::::::END OF STEGANOGRAPHY REGION::::::::::::::::::::::::::::::
#main()

#============================================TESTS==============================
#encrypt_to_image("hello world","test.png")
#decrypt_to_text("test.png")
#main(option = 1, image = 'bb.png', data = "hello world", output = 'worked.png')
#main(option = 2, image = 'worked.png', data = None, output = None)
test = encrypt("hello world", "1574")
test
decrypt(test, "1574")

#=========================================END OF REGION==========================