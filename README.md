# PasswordManager
In today’s digital landscape, where the security of personal and professional data is increasingly at risk, managing credentials securely is a critical necessity. The Credential Management System is designed to empower individuals with a secure, user-friendly solution for storing and managing sensitive information like usernames, passwords, and authentication tokens. 

Users often struggle to maintain strong, unique passwords across various platforms, which exposes them to significant security risks. The lack of multi-factor authentication (MFA) and poor password management practices exacerbate these vulnerabilities. There is a pressing need for a system that not only stores passwords securely but also encourages best practices in password creation and management.

The Credential Management System leverages a combination of hashing and encryption to store passwords securely. Using pure Python development, the system utilizes the bcrypt library for secure password hashing and PBKDF2HMAC for additional key derivation and encryption. Passwords are encrypted and stored locally on the user’s machine, ensuring that sensitive data is protected even in offline scenarios.

The system also integrates Two-Factor Authentication (2FA) using Google Authenticator, adding an extra layer of security to the authentication process. Before storing passwords, the system calculates their entropy to assess strength and checks against a database of commonly used passwords to ensure that weak passwords are not stored. This approach not only secures credentials but also educates users on the importance of strong, unique passwords.



How to run:-

1. Download the Google Authenticator App.
2. Run PasswordManagerMain.py
3. After registering a new account, open the saved QR Code in your machine and scan using Google Authenticator to register Two-Factor Authentication.
4. Login using the credentials.
