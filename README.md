# PasswordManager
Store Passwords securely using a combination of hashing and encryption.

Uses bcrypt and PBKDF2HMAC.

2FA using Google Authenticator.

Data is stored locally on the machine.

Calculates the entropy of password as well as checks if it is a commonly used password, in order to determine the overall strength of the password before storing it.

How to run:-

1. Download the Google Authenticator App.
2. Run PasswordManagerMain.py
3. After registering a new account, open the saved QR Code in your machine and scan using Google Authenticator to register Two-Factor Authentication.
4. Login using the credentials.
