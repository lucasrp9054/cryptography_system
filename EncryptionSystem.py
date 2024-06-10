
class EncryptionSystem:

    @staticmethod
    def main():
        # Entry point of the program
        # Example call to the method for choosing the encryption method
        EncryptionSystem.choose_encryption_method()

    @staticmethod
    def choose_encryption_method():
        # Method to choose the encryption method (symmetric or asymmetric)
        # Example control structure for method selection
        choice = EncryptionSystem.get_user_choice()
    
        while choice != 1 and choice != 2:
            
            print("Invalid option. Please choose 1 or 2.")
            choice = EncryptionSystem.get_user_choice()

        if choice == 1:
            # Call method for symmetric encryption/decryption
            EncryptionSystem.handle_symmetric_encryption()
        elif choice == 2:
            # Call method for asymmetric encryption/decryption
            EncryptionSystem.handle_asymmetric_encryption()
        else:
            print("Invalid option. Please choose 1 or 2.")

    @staticmethod
    def get_user_choice():

        # Get the user's choice
        print('Choose the encryption method to use:')
        print('1 for Symmetric\n2 for Asymmetric')
        number = input('Escolha: ')

        return int(number)

    @staticmethod
    def handle_symmetric_encryption():
        # Handle symmetric encryption
        print("You chose symmetric encryption.")
        return 0

    @staticmethod
    def handle_asymmetric_encryption():
        # Handle asymmetric encryption
        print("You chose asymmetric encryption.")
        return 0
