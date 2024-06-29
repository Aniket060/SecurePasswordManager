import os
import json
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import re
import pyotp
import time
import qrcode

class UserManager:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        
    def RegisterUser(self):
        if not re.match("^[a-zs]+$", self.username):
            print("Username must contain only lowercase letters")
            return
        
        if len(self.username) < 8:
            print("Username must be at least 8 characters long.")
            return
        
        auth_key = self.username
        totp = pyotp.TOTP(auth_key)
        uri = totp.provisioning_uri(name=self.username, issuer_name="CredManageApp")
        qrcode.make(uri).save(f"{self.username}_2fa.png")
        hashed_pwd = bcrypt.hashpw(self.password.encode('utf-8'), bcrypt.gensalt())
        store_pwd = hashed_pwd.decode('utf-8')
        user_data = {
            "Account Username": self.username,
            "Account Password": store_pwd,
        }

        filename = f"{self.username}.json"
        try:
            if os.path.exists(filename):
                print("User already exists.")
            else:
                with open(filename, "w") as f:
                    json.dump(user_data, f, indent=4)
                print("User registered successfully! Open Google Authenticator app and scan the saved QR Code. ")
        except IOError as e:
            print(f"Error: {e}")

    def LoginUser(self):
        filename = f"{self.username}.json"
        if os.path.exists(filename):  
            try:
                with open(filename, "r") as f:
                    data = json.load(f)
                
                if bcrypt.checkpw(self.password.encode('utf-8'), data["Account Password"].encode('utf-8')):
                    auth_key = self.username
                    totp = pyotp.TOTP(auth_key)
                    otp_input = input("Enter OTP: ")
                    
                    if len(otp_input) != 6 or not otp_input.isdigit():
                        print("Invalid OTP format. OTP should be 6 digits.")
                        return False
                    
                    if totp.verify(otp_input):
                        print("Login Successful.")
                        return True
                    else:
                        print("Login Failed. Incorrect OTP.")
                        return False
                else:
                    print("Login Failed. Incorrect Password.")
                    return False
            except (IOError, json.JSONDecodeError) as e:
                print(f"Error: {e}")
                return False
        else:
            print("User not found. Kindly Register.")
            return False

    def AddCredentials(self, app, username1, password1):
        if not app or not username1 or not password1:
            print("Application name, username, and password are required.")
            return
        
        kdf_salt = os.urandom(16)
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=kdf_salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = self.kdf.derive(self.password.encode('utf-8'))
        use_key = base64.urlsafe_b64encode(key)
        cipher = Fernet(use_key)
        
        try:
            enc_pwd = cipher.encrypt(password1.encode('utf-8'))
            
            filename = f"{self.username}.json"
            with open(filename, "r") as f:
                data = json.load(f)
            
            credentials = data.get("Credentials", {})
            credentials[app] = {
                "Username": username1,
                "Password": enc_pwd.decode('utf-8'),
                "ID": base64.urlsafe_b64encode(kdf_salt).decode('utf-8')
            }
            data["Credentials"] = credentials
            
            with open(filename, "w") as f:
                json.dump(data, f, indent=4)
            
            print("Added Successfully.")
        
        except (IOError, json.JSONDecodeError, ValueError) as e:
            print(f"Error: {e}")

    def DeleteCredentials(self, creds):
        filename = f"{self.username}.json"
        try:
            with open(filename, "r") as f:
                data = json.load(f)
            
            if creds in data["Credentials"]:
                data["Credentials"].pop(creds)
                
                with open(filename, "w") as f:
                    json.dump(data, f, indent=4)
                
                print("Deleted successfully.")
            else:
                print("Credentials not found.")
        
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error: {e}")

    def RetrieveCredentials(self):
        filename = f"{self.username}.json"
        try:
            with open(filename, "r") as f:
                data = json.load(f)
            
            print("Following are the Applications: ")
            for dict_key in data["Credentials"].keys():
                print(dict_key)
            
            cred2 = input("Which application's credentials would you like to view? ")
            
            if cred2 in data["Credentials"]:
                kdf_salt = base64.urlsafe_b64decode(data["Credentials"][cred2]["ID"])         
                
                self.kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=kdf_salt,
                    iterations=100000,
                    backend=default_backend()
                )
                
                key = self.kdf.derive(self.password.encode('utf-8'))
                use_key = base64.urlsafe_b64encode(key)
                cipher = Fernet(use_key)
                dec_pwd = cipher.decrypt(data["Credentials"][cred2]["Password"].encode('utf-8'))
                print(f"Password: {dec_pwd.decode('utf-8')}")
            
            else:
                print("Credentials not found.")
        
        except (IOError, json.JSONDecodeError, ValueError) as e:
            print(f"Error: {e}")

    def DeleteAccount(self):
        filename = f"{self.username}.json"
        confirm = input("Are you sure you want to delete your account? Press 'Yes' to confirm or 'No' to cancel. ")
        if confirm.lower() == "yes":
            try:
                os.remove(filename)
                print("Account Deleted Successfully.")
            except FileNotFoundError:
                print("Account not found.")
        
        else:
            print("Account Deletion Cancelled.")

def ForgotPassword():
    username = input("Enter username: ")
    filename = f"{username}.json"
    
    try:
        if os.path.exists(filename):
            with open(filename, "r") as f:
                data = json.load(f)
            
            if len(username) < 8:
                auth_key = username + 'x' * (8 - len(username))
                print(auth_key)
            else:
                auth_key = username
                print(auth_key)
            
            totp = pyotp.TOTP(auth_key)
            otp_input = input("Enter OTP: ")
            
            if len(otp_input) != 6 or not otp_input.isdigit():
                print("Invalid OTP format. OTP should be 6 digits.")
                return
            
            if totp.verify(otp_input):
                global pwd
                pwd = input("Enter New Password: ")
                
                while 0 <= PasswordStrength(pwd) <= 2:
                    val = input("Press 1 to continue. Press 0 to re-enter password: ")
                    
                    if val == '1':
                        break
                    elif val == '0':
                        pwd = input("Enter password: ")
                    else:
                        print("Invalid Option.")
                
                hashed_pwd = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
                store_pwd = hashed_pwd.decode('utf-8')
                user_data = {
                    "Account Username": username,
                    "Account Password": store_pwd
                }
                
                with open(filename, "r") as f:
                    data = json.load(f)
                
                data.update(user_data)
                
                with open(filename, "w") as f:                
                    json.dump(data, f, indent=4)
                
                print("Password Reset Successfully.")
            
            else:
                print("Incorrect OTP.")
        
        else:
            print("Invalid Username.")
    
    except (IOError, json.JSONDecodeError, ValueError) as e:
        print(f"Error: {e}")

def EntropyCheck(pwd):
    import math
    N = 0
    if any(char.isupper() for char in pwd):
        N += 26
    if any(char.islower() for char in pwd):
        N += 26
    if any(char.isdigit() for char in pwd):
        N += 10
    if any(not char.isalnum() for char in pwd):
        N += 32
    
    L = len(pwd)
    entropy = L * math.log2(N)
    
    if 0 < entropy <= 35:
        return 1
    elif 36 <= entropy <= 59:
        return 2
    elif 60 <= entropy <= 119:
        return 3
    elif entropy >= 120:
        return 4

def CommonPassword(password):
    with open("common passwords list.txt", "r") as f:
        pwd_set = set(f.read().splitlines())
    
    if password in pwd_set:
        return True
    else:
        return False

def PasswordStrength(pwd):
    if CommonPassword(pwd):
        print("Password Strength is Very Weak.")
        return 0
    elif EntropyCheck(pwd) == 1:
        print("Password Strength is Weak.")
        return 1
    elif EntropyCheck(pwd) == 2:
        print("Password Strength is Moderate.")
        return 2
    elif EntropyCheck(pwd) == 3:
        print("Password Strength is Strong.")
        return 3
    elif EntropyCheck(pwd) == 4:
        print("Password Strength is Very Strong.")
        return 4

