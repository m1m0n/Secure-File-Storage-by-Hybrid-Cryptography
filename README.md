## Secure File Storage in Cloud Using Hybrid Cryptography##

### Objective.
We introduce a solution to achieve the secrecy of the data during uploading to, downloading from,
and storing on the cloud then saving the decryption key secure through image steganography. This solution
combines both symmetric and asymmetric cryptography and steganography to achieve data integrity, security,
confidentiality.

# Features
* Secure files in AWS Cloud.
* Encryption and Decryption occurs in the user side
* Key is sent to your email ID using Stego .
* Pure-Python

# Getting Started

To get started with the code on this repo, you need to either clone or download this repo into your machine just as shown below;

```
git clone https://github.com/m1m0n/Secure-File-Storage-by-Hybrid-Cryptography.git
cd Secure-File-Storage-by-Hybrid-Cryptography
```

# Dependencies

Before you begin playing with the source code you might need to install deps just as shown below;

`pip3 install -r requirements.txt`

# Setting up AWS S3

For setting up AWS S3 for uploading and downloading files from the bucket you first need to setup your AWS
account and create a bucket.

Before starting you need to create an AWS account if you don’t have an account, by getting in [AWS](https://aws.amazon.com/) and create an account.
Then the user needs to set up an S3 bucket to be able to download and upload files from it, To do that you can follow this [Link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/creating-bucket.html) For creating a bucket and this to set the bucket [configration](https://towardsdatascience.com/how-to-upload-and-download-files-from-aws-s3-using-python-2022-4c9b787b15f2).


# Setting up Gmail account

The decryption phase of this process involves the use of your gmail account, although using this feature may affect in your privacy setting but in order to receive mail from third party you need to do this.

Google now doesn’t accept the login from less secure apps. So you need to go to [Google's Privacy Settings](https://myaccount.google.com/security) scroll to the bottom and turn ON “Allow less secure apps: ON”. You need to do this for the email ID you are adding in your Send as a section.

# Running the App
In order to run the app in your device, first you need to make some changes in the `hybrid.py` file. You need to modify the value of all those variables whose values are specified in between `< >`.

After changing the values of every variables,

`python3 main.py`

## Teammates
- https://github.com/Mostafa1Mahmoud
- https://github.com/mohamed-ali-5050
- https://github.com/muhammedhani