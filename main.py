import boto3
import argparse
from botocore.exceptions import ClientError
from sys import argv
from os import listdir
from functions import *


if __name__== "__main__":
    
    
    #create an ArgumentParser object
    parser = argparse.ArgumentParser(description = 'Secure File Storage Using AWS S3 buckets',usage=msg())
    #declare arguments
    
    gruop = parser.add_mutually_exclusive_group(required=True)
    gruop.add_argument('--encrypt','-e',help='File Encryption Option',action='store_true')
    gruop.add_argument('--decrypt','-d',help='File Decryption Option',action='store_true')
    gruop.add_argument('--list','-l', help="List Files in the Bucket",action='store_true')

    parser.add_argument('--filename','-f',type=str,help='File Name')
    parser.add_argument('--bucketname','-b',type=str,help='S3 Bucket Name')
    parser.add_argument('--image','-i',help='Image File that Contains Secret info')
    parser.add_argument('--mail','-m',help='E-mail to send decryption keys to it.')

    # if no args is passed show help menu
    args = parser.parse_args(args=None if argv[1:] else ['--help'])

    # info dict for storing :
        # - Publick key
        # - private key
        # - encrypted key (symmetric key after encrypting with asymmetric key )
    info = {}
    #[1]--------- if the user want to list the bucket content ------------
    try :
        if args.list and args.bucketname and bucket_exist(args.bucketname):
            s3 = boto3.resource('s3')
            my_bucket = s3.Bucket(args.bucketname)
            for my_bucket_object in my_bucket.objects.all():
                print("[+]",my_bucket_object.key)
        #[2] ------------- Ecryption process --------------------    
        elif args.encrypt and args.filename and args.bucketname and args.image and args.mail and bucket_exist(args.bucketname) and is_valid_email(args.mail):
            if args.image:
                try:
                    print("\n--> Searching in your input image ", args.image,"for a previous key to use...")
                    f = lsb_extract(args.image)
                    private_key = f["private_key"]
                    encrypted_key = f["encrypted_key"]
                    key = RSA_decrypt(private_key, encrypted_key) # symmetric key
                    
                    # pyAesCrypt.encryptFile() : used File Encryption using AES-CBC
                    pyAesCrypt.encryptFile(args.filename, args.filename+".enc", key)
                    print("\n--> Uploading",args.filename,"to",args.bucketname+" bucket...")
                    
                    r = bucket_upload_file(args.filename+".enc", args.bucketname, args.filename+".enc")
                    if r == True:
                        print("\n--> Your File Is Encrypted And Uploaded On The Given Bucket !")
                    else:
                        print(r[1])
                except:
                    print("\n--> The given image has no previous keys, we will generate a new one for you.")
                    #Obtains public key.
                    print("\n--> Generating RSA Public and Private keys......")
                    # pub = [n,e]
                    # prk = [d,n]
                    pub,prk=generate_key()        
                    info.update({"public_key" : pub,"private_key" : prk})
                
                    #Generates a fresh symmetric key for the data encapsulation scheme.
                    print("\n--> Generating AES Symmetric key......")
                    key = secrets.token_hex(32) # 32 bytes = 64 hex digits
                
                    encrypted_key = RSA_encrypt(pub, key)
                    info.update({"encrypted_key" : encrypted_key})

                    #dumps() : convert dict to str
                    #Here we apply stegnography

                    lsb_hide(args.image, "key.png", dumps(info))
                    print("\n--> Using Stegnography, All info needed for decryption process are saved in Key.png image")
                    
                    # pyAesCrypt.encryptFile() : used File Encryption using AES-CBC
                    pyAesCrypt.encryptFile(args.filename, args.filename+".enc", key)
                    print("\n--> Uploading",args.filename,"to",args.bucketname+" bucket...")
                    
                    r = bucket_upload_file(args.filename+".enc", args.bucketname, args.filename+".enc")
                    if r == True:
                        print("\n--> Your File Is Encrypted And Uploaded On The Given Bucket !")
                
                    else:
                        print(r[1])
                        exit()
                    # Here we send the email with the decryption info to the user
                    state = send_email(args.mail)
                    if state:
                        print("\n--> Email is sent Successfully!")
                    else:
                        print("\n--> An error occured during sending the email!!")
                        print(state[1])
        #[3] ------------- Decryption process --------------------

            # [1]- Extract the key from the stego image
            # [2]- Download the file from the bucket 
            # [3]- Decrypt the file using the key

                
        elif args.decrypt and args.filename and args.bucketname and args.image and bucket_exist(args.bucketname):
            print("\n--> Working on Decrypting your file......") 
            try:
                # extract the key from the stego image
                f = lsb_extract(args.image)
            except:
                print("\n--> The Given image has no previous keys ")
                exit()

            private_key = f["private_key"]
            encrypted_key = f["encrypted_key"]
        
            key = RSA_decrypt(private_key, encrypted_key) # symmetric key
            
            # download file from S3 Bucket
            if args.filename not in listdir("."):
                try:
                    s3 = boto3.client('s3')
                    s3.download_file(args.bucketname, args.filename ,args.filename)
                except Exception as e:
                    print("\n--> The file",args.filename,"not found in", args.bucketname)
                    exit()

            try:
                pyAesCrypt.decryptFile(args.filename, args.filename[:-4], key)  
                print("\n--> File is Decrypted Successfully!")  
            except Exception as e:
                print(e)
        else:
            print("\n--> Error in the Given Arguments!!!")
            parser.print_help()


    except Exception as e:
        print("\n --> Error in the Given Arguments, Check it again!")
        print(e)
        parser.print_help()
        