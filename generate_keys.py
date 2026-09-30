"""Generate hashed_pw.pkl in the original positional layout.

The hashes are now argon2 (argon2-cffi). Once every deployment has performed
the first-login migration, config/credentials.toml becomes the single truth
and this file is only a read-only compatibility source.
"""

from pathlib import Path

from argon2 import PasswordHasher

usernames = ["pparker", "rmiller"]
passwords = ["abc123", "def456"]

hasher = PasswordHasher()
hashed_passwords = [hasher.hash(password) for password in passwords]

file_path = Path(__file__).parent / "hashed_pw.pkl"
with file_path.open("wb") as file:
    import pickle

    pickle.dump(hashed_passwords, file)

print(f"wrote {len(hashed_passwords)} argon2 hashes for {usernames} to {file_path}")
