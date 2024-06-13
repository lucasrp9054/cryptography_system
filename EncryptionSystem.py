# Importing os module for operating system functionalities
import os

# Importing necessary components from cryptography library for encryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Importing default_backend from cryptography backend for cryptographic operations
from cryptography.hazmat.backends import default_backend

# Importing base64 module for base64 encoding and decoding functionalities
import base64

class EncryptionSystem:

    import os

class EncryptionSystem:
    # For Symmetric
    saved_single_key = ''     # Initialized as an empty string

    # For Asymmetric
    saved_public_key = ''     # Initialized as an empty string
    saved_private_key = ''    # Initialized as an empty string
    saved_p = 0               # Initialized as 0
    saved_q = 0               # Initialized as 0

    # For Symmetric and Asymmetric
    rollback = 0              # Initialized as 0
    saved_phrase = ''         # Initialized as an empty string

    @staticmethod
    def main():
        # Entry point of the program
        EncryptionSystem.get_user_action()

    @staticmethod
    def clear_screen():
        # Function to clear the terminal screen
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def restart_global_variables():

        saved_single_key = ''     
        saved_public_key = ''     
        saved_private_key = ''    
        saved_p = 0               
        saved_q = 0              
        rollback = 0              
        saved_phrase = ''         

        return 0

    @staticmethod
    def get_user_action():
        # Get the user's choice to encrypt or decrypt
        print("Welcome to the Encryption System!")
        while True:
            choice = input("Would you like to encrypt (E) or decrypt (D) a message? ").upper()
            if choice == "E":
                return EncryptionSystem.choose_encryption_method()
            elif choice == "D":
                return EncryptionSystem.choose_decryption_method()
            else:
                print("Invalid choice. Please enter 'E' for encryption or 'D' for decryption.")

    @staticmethod
    def get_user_choice():
        # Get the user's choice of encryption method
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
        encrypted_message = ''  # Initialize the variable outside the if block
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
            encrypted_message = base64.b64encode(ciphertext).decode()

            # Print the encrypted message
            print("Encrypted message:", encrypted_message)

        # Ask if the user wants to save the message and key
        while True:
            print(f"\nWould you like to save the message: {encrypted_message} and the key: {key} to apply the decryption method?")
            choice = input("Yes [Y] or No [N]? ").upper()
            if choice == 'Y':
                EncryptionSystem.saved_phrase = encrypted_message
                EncryptionSystem.saved_single_key = key
                EncryptionSystem.rollback = 0
                EncryptionSystem.symmetric_decryption()
                break  # Exit the loop if the user chooses to save
            elif choice == 'N':
                EncryptionSystem.saved_phrase = ''
                EncryptionSystem.saved_single_key = ''
                EncryptionSystem.rollback = 0
                EncryptionSystem.clear_screen()
                EncryptionSystem.get_user_action()
                break  # Exit the loop if the user chooses not to save
            else:
                EncryptionSystem.rollback = 1
                print("Please choose between [Y] or [N].")

    @staticmethod
    def symmetric_decryption():
        # Handle symmetric decryption using TripleDES algorithm
        EncryptionSystem.clear_screen()
        if EncryptionSystem.saved_single_key == '':
            print("You chose symmetric decryption.")
            # Get the key from the user and convert it to bytes
            while True:
                key = input("\nPlease insert your key (8 bytes): ").encode()
                # Check if the key is 8 bytes long
                if len(key) != 8:
                    print("Invalid key length. Please enter a key of length 8 bytes.")
                else:
                    break  # Exit the loop if the key is valid

            # Get the encrypted message from the user
            encrypted_message = input("Please enter the encrypted message: ")

        else: #If the user have chosen to save his previous encryption
            print("As we already have both variables:\n")
            print(f"Key = {EncryptionSystem.saved_single_key.decode()}")
            print(f"Cipher phrase = {EncryptionSystem.saved_phrase}")
            print("\nLet's proceed...\n")
            key = EncryptionSystem.saved_single_key
            encrypted_message = EncryptionSystem.saved_phrase
            
        # Decode the base64-encoded ciphertext
        ciphertext = base64.b64decode(encrypted_message)

        # Create a TripleDES cipher with CBC mode to decrypt the message.
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b'\0' * 8), backend=default_backend())

        # Create a decryptor object using the cipher to perform the decryption process.
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext using the decryptor object.
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Print the decrypted plaintext
        print("Decrypted message:", plaintext.decode())

        # Prompt the user to continue
        input('\nPress ENTER to continue...\n')

        # Reset global variables for the next operation
        EncryptionSystem.restart_global_variables()

        # Return to the main menu
        EncryptionSystem.get_user_action()

    @staticmethod
    def asymmetric_encryption():
        # Clear the terminal screen
        EncryptionSystem.clear_screen()

        if EncryptionSystem.rollback == 0:
            # Handle asymmetric encryption process
            print("You chose asymmetric encryption.")

            # Prompt the user to enter two prime numbers for RSA key generation
            print("Enter two prime numbers to generate RSA keys:")

            # Prompt user for prime numbers and save p
            p = EncryptionSystem.get_prime_number()
            EncryptionSystem.saved_p = p

            # Prompt user for prime numbers and save q
            q = EncryptionSystem.get_prime_number()
            EncryptionSystem.saved_q = q

            # Generate RSA keys
            public_key, private_key = EncryptionSystem.generate_RSA_keys(p, q)

            # Prompt user for message to encrypt
            message = input("Please enter the message to be encrypted: ")

            # Encrypt the message using RSA algorithm
            e, n = public_key
            encrypted_message = [pow(ord(char), e, n) for char in message]

            # Display generated keys and encrypted message
            print("Public Key:", public_key)
            print("Private Key:", private_key)
            print("Original message:", message)
            print("Encrypted message:", encrypted_message)

            # Ask user to save encryption details for decryption
            while True:
                print(f"\nWould you like to save the message: {encrypted_message} and the p: {p} and q: {q} values to apply the decryption method?")
                choice = input("Yes [Y] or No [N]? ").upper()
                if choice == 'Y':
                    EncryptionSystem.saved_phrase = encrypted_message
                    EncryptionSystem.saved_private_key = private_key
                    EncryptionSystem.saved_public_key = public_key
                    EncryptionSystem.rollback = 0
                    EncryptionSystem.asymmetric_decryption()
                    break  # Exit the loop if the user chooses to save
                elif choice == 'N':
                    EncryptionSystem.saved_phrase = ''
                    EncryptionSystem.saved_private_key = 0
                    EncryptionSystem.saved_public_key = 0
                    EncryptionSystem.rollback = 0
                    EncryptionSystem.clear_screen()
                    EncryptionSystem.get_user_action()
                    break  # Exit the loop if the user chooses not to save
                else:
                    EncryptionSystem.rollback = 1
                    print("Please choose between [Y] or [N].")

        else:
            # If rollback is set, continue with saved encryption details
            while True:
                print(f"\nWould you like to save the message: {encrypted_message} and the p: {p} and q: {q} values to apply the decryption method?")
                choice = input("Yes [Y] or No [N]? ")
                if choice == 'Y':
                    EncryptionSystem.saved_phrase = encrypted_message
                    EncryptionSystem.saved_private_key = private_key
                    EncryptionSystem.saved_public_key = public_key
                    EncryptionSystem.rollback = 0
                    EncryptionSystem.asymmetric_decryption()
                    break  # Exit the loop if the user chooses to save
                elif choice == 'N':
                    EncryptionSystem.saved_phrase = ''
                    EncryptionSystem.saved_private_key = 0
                    EncryptionSystem.saved_public_key = 0
                    EncryptionSystem.rollback = 0
                    EncryptionSystem.get_user_action()
                    break  # Exit the loop if the user chooses not to save
                else:
                    EncryptionSystem.rollback = 1
                    print("Please choose between [Y] or [N].")

    @staticmethod
    def asymmetric_decryption():
        # Clear the terminal screen
        EncryptionSystem.clear_screen()

        if EncryptionSystem.saved_private_key == '':
            # If no private key is saved, prompt the user to enter prime numbers for RSA key generation
            print("Enter two different prime numbers to generate RSA keys:")
            p = EncryptionSystem.get_prime_number()
            EncryptionSystem.saved_p = p

            q = EncryptionSystem.get_prime_number()
            EncryptionSystem.saved_q = q

            # Prompt user for message to decrypt
            message = input("Please enter the message to be decrypted: ")

            # Retrieve saved private key and modulus n
            d, n = EncryptionSystem.saved_private_key

            # Decrypt the message using RSA algorithm
            decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])

        else:
            # If a private key is saved, continue with saved details
            print("As we already have both variables:\n")
            print(f"P = {EncryptionSystem.saved_p}")
            print(f"Q = {EncryptionSystem.saved_q}\n")

            print("Leading us to:\n")
            print(f"Public Key = {EncryptionSystem.saved_public_key}")
            print(f"Private Key = {EncryptionSystem.saved_private_key}")
            print(f"Encrypted phrase = {EncryptionSystem.saved_phrase}")
            print("\nLet's proceed...\n")

            # Retrieve saved encryption details
            encrypted_message = EncryptionSystem.saved_phrase
            d, n = EncryptionSystem.saved_private_key

            # Decrypt the message using RSA algorithm
            decrypted_chars = [chr(pow(char, d, n)) for char in encrypted_message]
            decrypted_message = ''.join(decrypted_chars)

        # Display the decrypted message
        print("Decrypted message:", decrypted_message)

        # Prompt the user to continue
        input('\nPress ENTER to continue...\n')

        # Reset global variables for the next operation
        EncryptionSystem.restart_global_variables()

        #Clear the terminal
        EncryptionSystem.clear_screen()

        # Return to the main menu
        EncryptionSystem.get_user_action()

    @staticmethod
    def is_prime(n):
        """
        Check whether a number is prime.

        Args:
            n (int): The number to check for primality.

        Returns:
            bool: True if the number is prime, False otherwise.
        """

        if n == EncryptionSystem.saved_p:
            # If n is equal to the previously saved prime (to ensure different primes are used)
            return False    
        elif n <= 1:
            # Numbers less than or equal to 1 are not prime
            return False
        elif n == 2:
            # 2 is the only even prime number
            return False
        elif n == 3:
            # 3 is a prime number
            return True
        elif n % 2 == 0 or n % 3 == 0:
            # Numbers divisible by 2 or 3 (besides 2 and 3 themselves) are not prime
            return False

        # Check divisibility starting from 5 up to the square root of n
        i = 5
        while i * i <= n:
            if n % i == 0 or n % (i + 2) == 0:
                # If n is divisible by any number in the form of 6k ± 1, it's not prime
                return False
            i += 6

        # If no divisor is found, n is prime
        return True


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
            print("""
        Here are some suggested prime numbers that can be used to generate RSA keys:
        - 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
        - 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, ...
                Lower values may generate bad results.
        """)
            num = input("Please enter a prime number (except 2): ")
            try:
                num = int(num)
                if EncryptionSystem.is_prime(num):
                    print("Thank you for entering a prime number.\n")
                    return num
                else:
                    print("The number you entered is not a prime number or it was outside the expected range.\n Please try again.")
            except ValueError:
                print("Invalid input. Please enter a valid integer.")

    
    @staticmethod
    def gcd(a,b):

        """
        Computes the greatest common divisor of two numbers.
        
        Args:
            a (int): The first number.
            b (int): The second number.
        
        Returns:
            int: The greatest common divisor of a and b.
        """
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def generate_RSA_keys(p, q):
        n = p * q
        phi = (p - 1) * (q - 1)

        # Public exponent (e) selection
        e = 65537  # Common choice for public exponent (typically a Fermat prime)

        # Ensure e and phi are coprime
        while EncryptionSystem.gcd(e, phi) != 1:
            e += 2

        # Private exponent (d) calculation
        d = EncryptionSystem.modular_inverse(e, phi)

        # Public key (e, n), Private key (d, n)
        public_key = (e, n)
        private_key = (d, n)

        return public_key, private_key
    
    @staticmethod
    def modular_inverse(e, phi):
        """
        Computes the modular inverse of e modulo phi.
        
        Args:
            e (int): The number to find the inverse of.
            phi (int): The modulus.
        
        Returns:
            int: The modular inverse of e modulo phi.
        
        Raises:
            ValueError: If the modular inverse does not exist.
        """

        gcd, x, _ = EncryptionSystem.extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("The modular inverse does not exist.")
        return x % phi
    
    @staticmethod
    def extended_gcd(a, b):
        """
        Computes the greatest common divisor of a and b,
        as well as the coefficients of Bézout's identity.
        
        Args:
            a (int): The first number.
            b (int): The second number.
        
        Returns:
            tuple: (gcd, x, y) where gcd is the greatest common divisor
                   and x, y are the coefficients of Bézout's identity.
        """
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = EncryptionSystem.extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y


if __name__ == "__main__":
    EncryptionSystem.main()
