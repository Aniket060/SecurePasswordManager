import PasswordManagerCore

try:
    service = int(input("""Welcome to Credential Manager!
    Choose what you want to do by entering the associated number:
    1. Login
    2. Register
    3. Forgot/Reset Password\n"""))

    if service == 1:
        user = input("Enter username: ")
        pwd = input("Enter password: ")
        r1 = PasswordManagertest.UserManager(user, pwd)
        status = r1.LoginUser()
        
        if status:
            operation = int(input("""Enter the function number you want to perform:
            1. Add New Credentials
            2. Delete Existing Credentials
            3. Browse Credentials
            4. Delete Account\n"""))
            
            if operation == 1:
                app = input("Enter application name: ")
                username1 = input("Enter the username: ")
                password1 = input("Enter the password: ")
                r1.AddCredentials(app, username1, password1)
                
            elif operation == 2:
                creds = input("Enter the application name: ")
                r1.DeleteCredentials(creds)
                
            elif operation == 3:
                r1.RetrieveCredentials()
                
            elif operation == 4:
                r1.DeleteAccount()
        
    elif service == 2:
        user = input("Enter username: ")
        pwd = input("Enter password: ")
        
        # Validate password strength before proceeding
        s = PasswordManagertest.PasswordStrength(pwd)
        
        while 0 <= s <= 2:
            val = input("Press 1 to continue. Press 0 to re-enter password: ")
            
            if val == '1':
                break
            elif val == '0':
                pwd = input("Enter password: ")
                s = PasswordManagertest.PasswordStrength(pwd)
            else:
                print("Invalid Option.")
        
        r1 = PasswordManagertest.UserManager(user, pwd)
        r1.RegisterUser()

    elif service == 3:
        PasswordManagertest.ForgotPassword()

    else:
        print("Invalid Choice.")

except ValueError:
    print("Invalid input. Please enter a number.")
except Exception as e:
    print(f"An error occurred: {e}")
