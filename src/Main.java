import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Main {

    // AES (Advanced Encryption Standard)

    // ECB (Electronic Codebook)
    // svaki blok šifriranog teksta ne ovisi ni o jednom bloku otvorenog teksta obrađenom do točke
    // bez InitVector-a

    // CBC (Cipher Blocker Chaining)
    // svaki blok šifriranog teksta ovisi o svim blokovima otvorenog teksta obrađenim do točke
    // s InitVector-om

    // PKCS5Padding
    // Public-Key Cryptography Standards
    // If numberOfBytes(clearText) mod 8 == 7, PM = M + 0x01
    // If numberOfBytes(clearText) mod 8 == 6, PM = M + 0x0202
    // If numberOfBytes(clearText) mod 8 == 5, PM = M + 0x030303
    // If numberOfBytes(clearText) mod 8 == 4, PM = M + 0x04040404
    // If numberOfBytes(clearText) mod 8 == 3, PM = M + 0x0505050505
    // If numberOfBytes(clearText) mod 8 == 2, PM = M + 0x060606060606
    // If numberOfBytes(clearText) mod 8 == 1, PM = M + 0x07070707070707
    // If numberOfBytes(clearText) mod 8 == 0, PM = M + 0x0808080808080808
    private static final String[] TRANSFORMATION = {"AES/ECB/PKCS5Padding", "AES/CBC/PKCS5Padding", "AES/ECB/NoPadding", "AES/CBC/NoPadding"};
    private static final int[] AES_KEY_LENGTH = {128, 192, 256};

    // SHA
    // SHA1     160bits hash
    // SHA265   256bits hash
    // SHA265   512bits hash

    public static void main(String[] args) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            // generateKeyFromPassword
            String password = readFromConsole("Password: ", reader);
            String salt = readFromConsole("Salt: ", reader);

            // 0 - AES/ECB/PKCS5Padding
            // 1 - AES/CBC/PKCS5Padding
            // 2 - AES/ECB/NoPadding
            // 3 - AES/CBC/NoPadding
            String transformation = TRANSFORMATION[1];

            // AES
            String algorithm = transformation.split("/")[0];
            System.out.println("-- algorithm " + algorithm);

            // 0 - 128
            // 1 - 192
            // 2 - 256
            int aesKeyLength = AES_KEY_LENGTH[2];
            System.out.println("-- algorithmKeyLength " + aesKeyLength);

            String iterations = readFromConsole("Iterations count for KDF: ", reader);

            int numOfIterations;

            try {
                numOfIterations = Integer.parseInt(iterations);
            } catch(NumberFormatException numberFormatException) {
                System.err.println("Cannot parse Int " + numberFormatException.getMessage());
                return;
            }

            SecretKey secretKey = generateKeyFromPassword(password, salt.getBytes(), algorithm, numOfIterations, aesKeyLength);

            String inputFile = readFromConsole("Original file: ", reader);
            String encryptedFile = readFromConsole("Encrypted file: ", reader);

            // InitVector samo za CBC
            IvParameterSpec ivSpec = null;

            String blockCipher = transformation.split("/")[1];
            switch(blockCipher) {
                case "ECB" -> {
                    System.out.println("-- blockCipher ECB");
                }
                case "CBC" -> {
                    System.out.println("-- blockCipher CBC");
                    byte[] initVector = generateRandomIV(16);
                    ivSpec = new IvParameterSpec(initVector);
                    System.out.println("-- initVector " + Base64.getEncoder().encodeToString(initVector));
                }
            }

            System.out.println("-- padding " + transformation.split("/")[2]);

            Cipher cipherForEncrypt = null;
            try {
                cipherForEncrypt = initCipher(secretKey, Cipher.ENCRYPT_MODE, ivSpec, transformation);
            } catch(InvalidKeyException invalidKeyException) {
                System.err.println(invalidKeyException.getMessage() + " (" + aesKeyLength + "bits)");
                return;

            }

            byte[] encryptResult = null;
            try {
                encryptResult = algorithm(inputFile, encryptedFile, cipherForEncrypt);
            } catch (IllegalBlockSizeException illegalBlockSizeException) {
                byte[] inputBytes = new byte[(int) new File(inputFile).length()];
                System.err.println("Define Padding or change your file length from " + inputBytes.length + " to multiple of 16");
                return;
            }
            System.out.println("-- encryptedText " + Base64.getEncoder().encodeToString(encryptResult));

            String outputFile = readFromConsole("Decrypted file: ", reader);

            Cipher cipherForDencrypt = initCipher(secretKey, Cipher.DECRYPT_MODE, ivSpec, transformation);
            byte[] dencryptResult = algorithm(encryptedFile, outputFile, cipherForDencrypt);
            System.out.println("-- decryptedText " + new String(dencryptResult, "UTF-8"));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] generateRandomIV(int size) {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[size];
        random.nextBytes(iv);
        return iv;
    }

    private static SecretKey generateKeyFromPassword(String password, byte[] salt, String algorithm, int iterations, int aesKeyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // PBKDF2 (Password-based-Key-Derivative-Function)
        // KDF (Key Derivation Function)
        // Na temelju iterativnog izvođenja HMAC-a mnogo puta s istim Padding-om
        // Funkcija koja se koristi za generiranje ključeva (definirane duljine) iz lozinke, soli i iteracija

        // KDF sigurnosni zahtjevi
        // KDF mora biti u stanju izvesti ključeve koji su otporni na kriptoanalitičke napade, uključujući napade snage i napade rječnikom.
        // KDF treba biti otporan na različite vrste napada, uključujući napade na ključeve, kao što su napadi na znani ključ.
        // KDF mora osigurati da generirani ključevi budu jedinstveni, tj. različiti za različite početne ključeve ili zaporke.
        // Ključevi generirani pomoću KDF-a moraju biti slučajni - ne smiju biti predvidljivi ili koristiti determinističke algoritme.
        // KDF treba biti dovoljno brz da se može koristiti u stvarnom vremenu, ali i dovoljno siguran da izdrži napade.

        // HMAC (Keyed-Hash Message Authentication Code)
        // Izračun koda za provjeru autentičnosti poruke (MAC) koji uključuje kriptografsku hash funkciju (SHA) u kombinaciji s tajnim kriptografskim ključem
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        char[] passwordChars = password.toCharArray();

        // broj iteracija linearno povećava vrijeme izvršenja algoritma
        // Dužina AES ključa (aesKeyLength) ne utječe na vrijeme izvršavanja algoritma
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, iterations, aesKeyLength);
        SecretKey secretKey = factory.generateSecret(spec);

        System.out.println("-- secretKeyGenerate ");
        return new SecretKeySpec(secretKey.getEncoded(), algorithm);
    }

    private static byte[] algorithm(String inputFile, String outputfile, Cipher cipher) throws IOException, IllegalBlockSizeException, BadPaddingException {
        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int) new File(inputFile).length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = cipher.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(outputfile);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();

        return outputBytes;
    }

    private static Cipher initCipher(SecretKey secretKey, int mode, IvParameterSpec ivSpec, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(transformation);

        if (ivSpec == null) {
            cipher.init(mode, secretKey);
        } else {
            cipher.init(mode, secretKey, ivSpec);
        }

        return cipher;
    }

    private static String readFromConsole(String msg, BufferedReader reader) throws IOException {
        System.out.print(msg);
        return reader.readLine();
    }

}