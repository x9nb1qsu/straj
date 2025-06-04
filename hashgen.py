import hashlib

def hash_password(password):
    """Hashes a password using SHA256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Пример генерации хешей
my_password = "Admin111."
my_secret_word = "Admin1111."

hashed_password = hash_password(my_password)
hashed_secret_word = hash_password(my_secret_word)

print(f"Login: your_new_login")
print(f"Password Hash: {hashed_password}")
print(f"Secret Word Hash: {hashed_secret_word}")
print(f"Full Name: Your Full Name")
print(f"Role: admin_or_security")