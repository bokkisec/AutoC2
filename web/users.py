import argparse
import hashlib

def register(user, pw):
    # Hash the password with SHA-256
    hashed_pw = hashlib.sha256(pw.encode()).hexdigest()
    
    # Format the result
    result = f"{user}:{hashed_pw}\n"
    
    # Append to the creds.db file
    with open("creds.db", "a") as file:
        file.write(result)

def validate_user(user, pw):
    # Hash given password
    hashed_pw = hashlib.sha256(pw.encode()).hexdigest()

    # Format the result
    login_attempt = f"{user}:{hashed_pw}\n"

    # Compare with entries in creds.db
    with open("creds.db", "r") as file:
        for line in file:
            if line == login_attempt:
                return True
    return False

if __name__=="__main__":
    # Parse args
    parser = argparse.ArgumentParser(description="Register user")
    parser.add_argument("-u", "--user", required=True, help="Username")
    parser.add_argument("-p", "--pw", required=True, help="Password")
    args = parser.parse_args()

    # Register
    register(args.user, args.pw)
