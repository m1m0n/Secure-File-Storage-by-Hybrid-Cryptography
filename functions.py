import random
from Crypto.Util import number
from Crypto.Util.number import isPrime
from math import gcd
import secrets
import pyAesCrypt 
from stegano import lsb
from json import dumps,loads
import smtplib
from email.message import EmailMessage
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import boto3
from botocore.exceptions import ClientError 
import re
from SECRET import *


def multiplicative_inverse(a, b):
        """Euclid's extended algorithm"""
        x = 0
        y = 1
        lx = 1
        ly = 0
        oa = a 
        ob = b  
        while b != 0:
            q = a // b
            (a, b) = (b, a % b)
            (x, lx) = ((lx - (q * x)), x)
            (y, ly) = ((ly - (q * y)), y)
        if lx < 0:
            lx += ob  
        if ly < 0:
            ly += oa  
        return lx

def generate_key(size=512):
    # Generate Prime numbers = p,q
    p = number.getPrime(size)
    q = number.getPrime(size)

    if not (isPrime(p) and isPrime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    n = p * q
    phi = (p-1) * (q-1)
    e = 65537
    # e = random.randrange(1, phi)
    # g = gcd(e, phi)
    # while g != 1:
    #     e = random.randrange(1, phi)
    #     g = gcd(e, phi)
    d = multiplicative_inverse(e, phi)
    return [[n, e], [d, n]]

def fast_expo(b, e, m):
    # https://github.com/csknk/fast-modular-exponentiation
    r = 1
    if 1 & e: # first 1 set the base
        r = b
    while e:
        e >>= 1 # bit shift operator, dividing e by 2
        b = (b * b) % m
        if e & 1: # if e is odd
            r = (r * b) % m
    return r

def RSA_encrypt(pk, plaintext):
    # Y = X ** e mod n 
    n = pk[0]
    e = pk[1]
    # fast_exp() ==> used to fast modular exponentiation which used in Y = X ** e mod n
    c = [fast_expo(ord(char), e, n) for char in plaintext] # this line === to the next block of commented code
    # c = []
    # for char in plaintext:
    #     c.append(fast_exp(char, e, n))
    return c

def RSA_decrypt(prk, ciphertext):
    # X = Y**d mod n
    d = prk[0]
    n = prk[1]
    m = [chr(fast_expo(char, d, n)) for char in ciphertext]
    return "".join(m) # join() = convert key from list to str


def bucket_upload_file(file_name, bucket, object_name=None):
    if object_name is None:
        object_name = file_name
    # Upload the file
    s3_client = boto3.client('s3') # boto3 module used to upload files to AWS S3 buckets
    try:
        response = s3_client.upload_file(file_name, bucket, object_name) # returns None
        return True 
    except Exception as e:
        return False,e

def lsb_hide(in_img, out_img, msg):
	lsb.hide(in_img, msg).save(out_img)

def lsb_extract(img):
    # loads() : convert str to dict
    return loads(lsb.reveal(img))


def send_email(mail):
    try:
        mail_content = """Hello, \nThis mail contains all those important details that you will need to access your file.. 
                \nIn this mail we are sending an image that helps you to decrypt your files you had uploaded to AWS.
                \nThank You."""
        
        sender_address = SENDER_EMAIL
        sender_pass = SENDER_PASS
        
        receiver_address = mail
        message = MIMEMultipart()
        message['From'] = sender_address
        message['To'] = receiver_address
        message['Subject'] = 'Important Keys for Decryption'
        message.attach(MIMEText(mail_content, 'plain'))
        attach_file_name = (r"key.png")
        attach_file = open(attach_file_name, 'rb') # Open the file as binary mode
        payload = MIMEBase('image', 'png')
        payload.set_payload((attach_file).read())
        encoders.encode_base64(payload) #encode the attachment
        #add payload header with filename
        payload.add_header('Content-Decomposition', 'attachment', filename=attach_file_name)
        message.attach(payload)
        #Create SMTP session for sending the mail
        session = smtplib.SMTP('smtp.gmail.com', 587) #use gmail with port
        session.starttls() #enable security
        session.login(sender_address, sender_pass) #login with mail_id and password
        text = message.as_string()
        session.sendmail(sender_address, receiver_address, text)
        session.quit()
        return True
    except Exception as e:
        return False,e
    
def bucket_exist(bucket):
    s3 = boto3.resource('s3')
    if s3.Bucket(bucket) in s3.buckets.all():
        return True
    else:
        return False


def is_valid_email(email):
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
    if re.fullmatch(regex, email):
        return True
    else:
        return False
