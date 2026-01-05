def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            result += char
    return result

def xor_encrypt(text, key):
    """Encrypt text using XOR cipher. Key must be 0 and 255."""
    if not (0 <= key <= 255):
        raise ValueError("Key must be between 0 and 255.")

    encrypted_bytes = bytes([ord(char) ^ key for char in text])
    return encrypted_bytes.hex()  # return hex string


def xor_decrypt(ciphertext_hex, key):
    """Decrypt XOR hex string back to text."""
    if not (0 <= key <= 255):
        raise ValueError("Key must be between 0 and 255.")

    encrypted_bytes = bytes.fromhex(ciphertext_hex)
    decrypted_chars = [chr(b ^ key) for b in encrypted_bytes]
    return "".join(decrypted_chars)

if __name__ == "__main__":
    print("Testing XOR Cipher:")
    encrypted = xor_encrypt("HELLO", 42)
    print("Encrypted:", encrypted)

    decrypted = xor_decrypt(encrypted, 42)
    print("Decrypted:", decrypted)

def _clean_key(key):
    """Remove non-letters and convert to uppercase."""
    cleaned = ''.join(ch.upper() for ch in key if ch.isalpha())
    if not cleaned:
        raise ValueError("Key must contain at least one letter.")
    return cleaned


def vigenere_encrypt(text, key):
    """Encrypt text using the Vigenère cipher."""
    key = _clean_key(key)
    result = []
    key_index = 0

    for ch in text:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            shift = ord(key[key_index % len(key)]) - ord('A')
            offset = (ord(ch) - ord(base) + shift) % 26
            result.append(chr(ord(base) + offset))
            key_index += 1
        else:
            result.append(ch)

    return ''.join(result)


def vigenere_decrypt(text, key):
    """Decrypt text using the Vigenère cipher."""
    key = _clean_key(key)
    result = []
    key_index = 0

    for ch in text:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            shift = ord(key[key_index % len(key)]) - ord('A')
            offset = (ord(ch) - ord(base) - shift) % 26
            result.append(chr(ord(base) + offset))
            key_index += 1
        else:
            result.append(ch)

    return ''.join(result)

print("\nTesting Vigenère Cipher:")
encrypted_v = vigenere_encrypt("HELLO WORLD", "KEY")
print("Encrypted:", encrypted_v)

decrypted_v = vigenere_decrypt(encrypted_v, "KEY")
print("Decrypted:", decrypted_v)

def atbash_transform(text):
    """Apply Atbash cipher (same for encrypt and decrypt)."""
    result = []
    for ch in text:
        if ch.isupper():
            offset = ord('Z') - (ord(ch) - ord('A'))
            result.append(chr(offset))
        elif ch.islower():
            offset = ord('z') - (ord(ch) - ord('a'))
            result.append(chr(offset))
        else:
            result.append(ch)
    return ''.join(result)


def atbash_encrypt(text):
    return atbash_transform(text)


def atbash_decrypt(text):
    return atbash_transform(text)

print("\nTesting Atbash Cipher:")
encrypted_a = atbash_encrypt("HELLO WORLD")
print("Encrypted:", encrypted_a)

decrypted_a = atbash_decrypt(encrypted_a)
print("Decrypted:", decrypted_a)

def run_menu():
    print("\n=== BASIC ENCRYPTION TOOL ===")
    print("Choose a cipher:")
    print("1. Caesar Cipher")
    print("2. XOR Cipher")
    print("3. Vigenère Cipher")
    print("4. Atbash Cipher")
    print("5. Exit")

    choice = input("Enter your choice (1-5): ").strip()

    if choice == "5":
        print("Goodbye!")
        return

    mode = input("Encrypt (e) or Decrypt (d): ").strip().lower()
    if mode not in ("e", "d"):
        print("Invalid mode.")
        return

    text = input("Enter your text: ")

    # Caesar Cipher
    if choice == "1":
        shift = int(input("Enter shift value (e.g., 3): "))
        if mode == "e":
            result = caesar_encrypt(text, shift)
        else:
            result = caesar_encrypt(text, -shift)

    # XOR Cipher
    elif choice == "2":
        key = int(input("Enter key (0-255): "))
        if mode == "e":
            result = xor_encrypt(text, key)
        else:
            result = xor_decrypt(text, key)

    # Vigenère Cipher
    elif choice == "3":
        key = input("Enter Vigenère key (letters only): ")
        if mode == "e":
            result = vigenere_encrypt(text, key)
        else:
            result = vigenere_decrypt(text, key)

    # Atbash Cipher
    elif choice == "4":
        result = atbash_encrypt(text) if mode == "e" else atbash_decrypt(text)

    else:
        print("Invalid choice.")
        return

    print("\n=== RESULT ===")
    print(result)

if __name__ == "__main__":
    while True:
        run_menu()
        again = input("\nDo you want to run again? (y/n): ").strip().lower()
        if again != "y":
            print("Exiting program.")
            break