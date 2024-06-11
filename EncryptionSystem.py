import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import base64

class EncryptionSystem:

    #For Symmetric and Asymetric
    saved_phrase = ''  # Initialized as an empty string
    saved_key = ''     # Initialized as an empty string
    rollback = 0       # Initialized as 0

    @staticmethod
    def main():
        # Entry point of the program
        EncryptionSystem.get_user_action()

    @staticmethod
    def clear_screen():
        # Function to clear the terminal screen
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def get_user_action():
        # Get the user's choice
        print("Welcome to the Encryption System!")
        choice = input("Would you like to encrypt (E) or decrypt (D) a message? ").upper()
        while True:
            if choice == "E":
                return EncryptionSystem.choose_encryption_method()
            elif choice == "D":
                return EncryptionSystem.choose_decryption_method()
            else:
                print("Invalid choice.")

    @staticmethod
    def get_user_choice():
        # Get the user's choice
        print('\nChoose the method to use:')
        print('1. Symmetric\n2. Asymmetric\n3. More info')
        number = input('Choice: ')
        try:
            return int(number)
        except ValueError:
            return 0

    @staticmethod
    def choose_encryption_method():
        # Method to choose the encryption method (symmetric or asymmetric)
        while True:
            choice = EncryptionSystem.get_user_choice()
            if choice == 1:
                EncryptionSystem.clear_screen()
                EncryptionSystem.symmetric_encryption()
                break
            elif choice == 2:
                EncryptionSystem.clear_screen()
                EncryptionSystem.asymmetric_encryption()
                break
            elif choice == 3:
                EncryptionSystem.clear_screen()
                EncryptionSystem.more_info()
            else:
                EncryptionSystem.clear_screen()
                print("Invalid option. Please choose 1, 2, or 3.")
                input('Press ENTER to continue...\n')

    @staticmethod
    def choose_decryption_method():
        # Method to choose the decryption method (symmetric or asymmetric)
        while True:
            choice = EncryptionSystem.get_user_choice()
            if choice == 1:
                EncryptionSystem.clear_screen()
                EncryptionSystem.symmetric_decryption()
                break
            elif choice == 2:
                EncryptionSystem.clear_screen()
                EncryptionSystem.asymmetric_decryption()
                break
            elif choice == 3:
                EncryptionSystem.clear_screen()
                EncryptionSystem.more_info()
            else:
                EncryptionSystem.clear_screen()
                print("Invalid option. Please choose 1, 2, or 3.")
                input('Press ENTER to continue...\n')

    @staticmethod
    def more_info():
        # Provide information on encryption methods
        info_text = (
            "Info\n\n"
            "Symmetric Encryption\n"
            "- Key Usage: Same key for encryption and decryption.\n"
            "- Performance: Faster.\n"
            "- Security: Key must be kept secret.\n"
            "In short: One key for both encryption and decryption.\n\n"
            "Asymmetric Encryption\n"
            "- Key Usage: Public key for encryption, private key for decryption.\n"
            "- Performance: Slower.\n"
            "- Security: Public key is shared, private key is secret.\n"
            "In short: Public key for encryption, private key for decryption.\n"
        )
        print(info_text)
        input('Press ENTER to return...\n')
        EncryptionSystem.clear_screen()
        
    @staticmethod
    def symmetric_encryption():
        # Handle symmetric encryption using TripleDES algorithm
        EncryptionSystem.clear_screen()
        encoded_ciphertext = ''  # Initialize the variable outside the if block
        key = ''                 # Initialize the variable outside the if block

        if EncryptionSystem.rollback == 0:
            print("You chose symmetric encryption.")

            while True:
                # Get the key from the user and convert it to bytes
                key = input("Please insert your key (8 bytes): ").encode()

                # Check if the key is 8 bytes long
                if len(key) != 8:
                    print("Invalid key length. Please enter a key of length 8 bytes.")
                else:
                    break  # Exit the loop if the key is valid

            # Get the message from the user and convert it to bytes
            message = input("Please enter the message to be encrypted: ").encode()

            # Pad the message to a multiple of 8 bytes
            if len(message) % 8 != 0:
                # If the message length is not a multiple of 8 bytes, pad it with spaces
                message += b' ' * (8 - len(message) % 8)

            # Create a TripleDES cipher with CBC mode to encrypt the message.
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b'\0' * 8), backend=default_backend())

            # Create an encryptor object using the cipher to perform the encryption process.
            encryptor = cipher.encryptor()

            # Encrypt the message using the encryptor object.
            ciphertext = encryptor.update(message) + encryptor.finalize()

            # Encode the ciphertext using base64 encoding
            encoded_ciphertext = base64.b64encode(ciphertext).decode()

            # Print the encrypted message
            print("Encrypted message:", encoded_ciphertext)

        # Ask if the user wants to save the message and key
        while True:
            print(f"\nWould you like to save the message: {encoded_ciphertext} and the key: {key} to apply the decryption method?")
            choice = input("Yes [Y] or No [N]? ")
            if choice == 'Y':
                EncryptionSystem.saved_phrase = encoded_ciphertext
                EncryptionSystem.saved_key = key
                EncryptionSystem.rollback = 0
                EncryptionSystem.symmetric_decryption()
                break  # Exit the loop if the user chooses to save
            elif choice == 'N':
                EncryptionSystem.saved_phrase = ''
                EncryptionSystem.saved_key = ''
                EncryptionSystem.rollback = 0
                EncryptionSystem.get_user_action()
                break  # Exit the loop if the user chooses not to save
            else:
                print("Please choose between [Y] or [N].")

    @staticmethod
    def symmetric_decryption():
        # Handle symmetric decryption using TripleDES algorithm
        EncryptionSystem.clear_screen()
        if EncryptionSystem.saved_key == '':
            print("You chose symmetric decryption.")
            # Get the key from the user and convert it to bytes
            while True:
                key = input("\nPlease insert your key (8 bytes): ").encode()
                # Check if the key is 8 bytes long
                if len(key) != 8:
                    print("Invalid key length. Please enter a key of length 8 bytes.")
                else:
                    break  # Exit the loop if the key is valid

            # Get the message to be decrypted from the user and convert it to bytes
            encoded_ciphertext = input("Please enter the encrypted message: ")

        else:
            print("As we already have both variables:\n")
            print(f"Key = {EncryptionSystem.saved_key.decode()}")
            print(f"Cipher phrase = {EncryptionSystem.saved_phrase}")
            print("\nLet's proceed...\n")
            key = EncryptionSystem.saved_key
            encoded_ciphertext = EncryptionSystem.saved_phrase

        ciphertext = base64.b64decode(encoded_ciphertext)

        # Create a TripleDES cipher with CBC mode to decrypt the message.
        # TripleDES (also known as DESede) is a symmetric encryption algorithm that encrypts data in blocks of 64 bits.
        # CBC (Cipher Block Chaining) is a mode of operation for block ciphers, which introduces an Initialization Vector (IV) to each block of plaintext
        # before encryption to ensure that identical plaintext blocks are not encrypted to the same ciphertext blocks.
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b'\0' * 8), backend=default_backend())

        # Create a decryptor object using the cipher to perform the decryption process.
        # The decryptor object is responsible for applying the decryption algorithm (TripleDES in CBC mode) to the input data (ciphertext).
        # It handles the decryption of the data chunk by chunk and manages any necessary padding and finalization steps.
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext using the decryptor object.
        # The decryptor object applies the TripleDES decryption algorithm in CBC mode to the input ciphertext.
        # The update() method processes the ciphertext in chunks and returns the intermediate plaintext.
        # The finalize() method completes the decryption process and returns the remaining plaintext.
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Print the decrypted plaintext
        print("Decrypted message:", plaintext.decode())

    @staticmethod
    def asymmetric_encryption():
        # Handle asymmetric encryption
        EncryptionSystem.clear_screen()
        print("You chose asymmetric encryption.")

        # Prompt the user to enter two prime numbers for RSA key generation
        print("Enter two prime numbers to generate RSA keys:")
        p = EncryptionSystem.get_prime_number()
        q = EncryptionSystem.get_prime_number()
        
        # Check if p and q are valid prime numbers
        if not EncryptionSystem.is_prime(p) or not EncryptionSystem.is_prime(q):
            print("Invalid prime numbers. Please choose valid prime numbers.")
            return
        
        # Generate RSA key
        key = EncryptionSystem.rsa_key_generation(p, q)
        
        # Message to encrypt
        message = input("Please enter the message to be encrypted: ")
        
        # Encrypt the message using the RSA key
        encrypted_message = EncryptionSystem.rsa_asymmetric_encryption(message, key)
        
        # Print original and encrypted messages
        print("Original message:", message)
        print("Encrypted message:", encrypted_message)

        # Ask if the user wants to save the message and key
        while True:
            print(f"\nWould you like to save the encrypted message and the key to apply the decryption method?")
            choice = input("Yes [Y] or No [N]? ")
            if choice == 'Y':
                EncryptionSystem.saved_phrase = encrypted_message
                EncryptionSystem.saved_key = key
                EncryptionSystem.rollback = 0
                EncryptionSystem.asymmetric_decryption()
                break  # Exit the loop if the user chooses to save
            elif choice == 'N':
                EncryptionSystem.saved_phrase = ''
                EncryptionSystem.saved_key = ''
                EncryptionSystem.rollback = 0
                EncryptionSystem.get_user_action()
                break  # Exit the loop if the user chooses not to save
            else:
                print("Please choose between [Y] or [N].")


    @staticmethod
    def asymmetric_decryption():
        # Handle asymmetric decryption
        EncryptionSystem.clear_screen()

        if EncryptionSystem.saved_key == '':
            # Prompt the user to enter two prime numbers for RSA key generation
            print("Enter two prime numbers to generate RSA keys:")
            p = EncryptionSystem.get_prime_number()
            q = EncryptionSystem.get_prime_number()
            
            # Generate RSA key
            key = EncryptionSystem.rsa_key_generation(p, q)

            # Get the message to be decrypted from the user and convert it to bytes
            encoded_ciphertext = input("Please enter the encrypted message: ")

        else:
            print("As we already have both variables:\n")
            print(f"Key = {EncryptionSystem.saved_key.decode()}")
            print(f"Cipher phrase = {EncryptionSystem.saved_phrase}")
            print("\nLet's proceed...\n")
            key = EncryptionSystem.saved_key
            encoded_ciphertext = EncryptionSystem.saved_phrase
        
        # Decrypt the message using the same RSA key
        decrypted_message = EncryptionSystem.rsa_asymmetric_decryption(encoded_ciphertext, key)
        
        print("Encrypted message:", encoded_ciphertext)
        print("Decrypted message:", decrypted_message)

        return 0

    
    
    @staticmethod
    def get_prime_number():
        """
        Function to prompt the user to enter a prime number.
        This function checks if the input is a prime number using the is_prime function.
        If the input is not a prime number, it prompts the user to try again.
        Returns:
            int: A prime number entered by the user.
        """
        while True:
            num = input("Please enter a prime number: ")
            try:
                num = int(num)
                if EncryptionSystem.is_prime(num):
                    EncryptionSystem.clear_screen()
                    return num
                else:
                    print("The number you entered is not prime. Please try again.")
                    input('Press ENTER to continue...\n')
                    EncryptionSystem.clear_screen()
            except ValueError:
                print("Invalid input. Please enter a valid integer.")

    @staticmethod
    def is_prime(n):
        """
        Function to check whether a number is prime or not.
        Args:
            n (int): The number to be checked for primality.
        Returns:
            bool: True if the number is prime, False otherwise.
        """
        if n <= 1:
            # If the number is less than or equal to 1, it is not prime
            return False
        elif n <= 3:
            # If the number is 2 or 3, it is prime
            return True
        elif n % 2 == 0 or n % 3 == 0:
            # If the number is divisible by 2 or 3, it is not prime
            return False
        i = 5
        while i * i <= n:
            # Loop through potential factors of the number starting from 5
            if n % i == 0 or n % (i + 2) == 0:
                # If the number is divisible by any of these factors, it is not prime
                return False
            i += 6
        # If no factors are found, the number is prime
        return True
    
    @staticmethod
    def rsa_key_generation(p, q):
        """
        Generates RSA public and private keys based on two prime numbers.
        
        Args:
        - p (int): First prime number.
        - q (int): Second prime number.
        
        Returns:
        - RSA key object.
        """
        # Calculate modulus and totient
        modulus = p * q
        totient = (p - 1) * (q - 1)
        
        # Choose public exponent (usually 65537 according to internet forums)
        public_exponent = 65537
        
        # Calculate private exponent
        private_exponent = pow(public_exponent, -1, totient)
        
        # Construct RSA key
        key = RSA.construct((modulus, public_exponent, private_exponent, p, q))
        
        return key



    @staticmethod
    def rsa_asymmetric_encryption(message, key):
        """
        Encrypts a message using RSA encryption.
        
        Args:
        - message (str): Message to encrypt.
        - key (RSA key object): Public or private RSA key.
        
        Returns:
        - bytes: Encrypted message.
        """
        # Create RSA cipher object
        cipher_rsa = PKCS1_OAEP.new(key)
        
        # Encrypt the message
        encrypted_message = cipher_rsa.encrypt(message.encode())
        
        return encrypted_message

    @staticmethod
    def rsa_asymmetric_decryption(encrypted_message, key):
        """
        Decrypts a message using RSA decryption.
        
        Args:
        - encrypted_message (bytes): Encrypted message.
        - key (RSA key object): Public or private RSA key.
        
        Returns:
        - str: Decrypted message.
        """
        # Create RSA cipher object
        cipher_rsa = PKCS1_OAEP.new(key)
        
        # Decrypt the message
        decrypted_message = cipher_rsa.decrypt(encrypted_message)
        
        return decrypted_message.decode()



if __name__ == "__main__":
    EncryptionSystem.main()
