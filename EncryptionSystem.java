public class EncryptionSystem {

    public static void main(String[] args) {
        // Entry point of the program

        // Example call to the method for choosing the encryption method
        chooseEncryptionMethod();
    }

    public static void chooseEncryptionMethod() {
        // Method to choose the encryption method (symmetric or asymmetric)

        // Example control structure for method selection
        int choice = getUserChoice();
        switch (choice) {
            case 1:
                // Call method for symmetric encryption/decryption
                handleSymmetricEncryption();
                break;
            case 2:
                // Call method for asymmetric encryption/decryption
                handleAsymmetricEncryption();
                break;
            default:
                System.out.println("Invalid option. Please choose 1 or 2.");
    }
    public static int getUserChoice(){

        int number = 0;

        return number;

    }

    public static int handleSymmetricEncryption(){


        return 0;

    }

    public static int handleAsymmetricEncryption(){


        return 0;

    }
}