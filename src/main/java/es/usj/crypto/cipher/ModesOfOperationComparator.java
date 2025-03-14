package es.usj.crypto.cipher;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Demonstrates how Cipher Algorithm modes of operation (ECB and CBC) work
 * for block cipher encryption algorithms like DES and AES.
 * <p>
 * An input BMP image is encrypted using DES and AES in different modes (ECB and CBC),
 * and the encrypted image is saved as a new file.
 * </p>
 * <p>
 * Note: ECB (Electronic Code Book) and CBC (Cipher Block Chaining) are two common modes
 * of operation for block ciphers. ECB processes each block independently, while CBC introduces
 * chaining, meaning each block depends on the encryption of the previous block.
 * </p>
 */
public class ModesOfOperationComparator {

    /**
     * Path to the folder where encrypted BMP files will be saved.
     * Adjust this path to a valid directory on your system.
     */
    public static final String OUTPUT_FOLDER = "/Users/angel.fernandoborroy/Downloads/tmp/";

    /**
     * BMP header length in bytes (54 bytes for BMP images).
     * The header is preserved unencrypted so that the image format remains valid.
     */
    public static final int BMP_BYTE_HEADER_LENGTH = 54;

    /**
     * Input BMP file name (located in the resources folder).
     * The file extension is removed to generate output file names for encrypted images.
     */
    static String fileNameInput = "logo-usj.bmp";
    static String fileNameInputNoExt = fileNameInput.substring(0, fileNameInput.indexOf("."));

    /**
     * Main method to demonstrate the encryption of a BMP image using DES and AES
     * with different modes of operation (ECB and CBC).
     * <p>
     * The encrypted files will be saved with appropriate names indicating the cipher and mode used.
     * </p>
     *
     * @param args command-line arguments (not used).
     * @throws Exception if any cryptographic or I/O error occurs.
     */
    public static void main(String... args) throws Exception {

        // Encrypt the image using DES and AES ciphers with different modes of operation.
        // ECB (Electronic Code Book) and CBC (Cipher Block Chaining) are demonstrated.
        encrypt("DES/ECB/PKCS5Padding");
        encrypt("DES/CBC/PKCS5Padding");

        encrypt("AES/ECB/PKCS5Padding");
        encrypt("AES/CBC/PKCS5Padding");
    }

    /**
     * Encrypts the input BMP image using the specified cipher transformation and saves the
     * encrypted image as a new BMP file.
     * <p>
     * The BMP header is left unencrypted to ensure the output file can still be recognized
     * as a valid BMP image. Only the image data (pixels) is encrypted.
     * </p>
     *
     * @param transformation the cryptographic transformation to use (e.g., "DES/ECB/PKCS5Padding").
     *                       The transformation string includes the algorithm, mode of operation, and padding scheme.
     * @throws Exception if an error occurs during the encryption process.
     */
    private static void encrypt(String transformation) throws Exception {

        // Create a Cipher instance using the specified transformation.
        Cipher cipher = Cipher.getInstance(transformation);

        // Extract the algorithm name from the transformation string (e.g., "DES" or "AES").
        String algorithm = transformation.substring(0, transformation.indexOf("/"));

        // Generate a secret key for the chosen algorithm (DES or AES).
        SecretKey secretKey = KeyGenerator.getInstance(algorithm).generateKey();

        // Initialize the Cipher in ENCRYPT_MODE with the generated secret key.
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Determine the output file name based on the cipher and mode of operation.
        String fileNameOutput = getFileName(transformation);

        // Load the input BMP file, prepare the output file, and apply the encryption.
        try (InputStream fileIn = ModesOfOperationComparator.class.getClassLoader().getResourceAsStream(fileNameInput);
             FileOutputStream fileOut = new FileOutputStream(OUTPUT_FOLDER + fileNameOutput);
             CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)) {

            // Read the entire BMP file into a byte array.
            byte[] inputBmp = fileIn.readAllBytes();

            // Separate the BMP header (54 bytes) from the image data.
            byte[] header = Arrays.copyOfRange(inputBmp, 0, BMP_BYTE_HEADER_LENGTH);
            byte[] imgData = Arrays.copyOfRange(inputBmp, BMP_BYTE_HEADER_LENGTH, inputBmp.length);

            // Write the unencrypted header to the output file.
            fileOut.write(header);
            fileOut.flush();

            // Encrypt and write the image data (the pixels) to the output file.
            cipherOut.write(imgData);
        }
    }

    /**
     * Generates the output file name for the encrypted BMP image.
     * The file name includes the original input file name, the cipher algorithm,
     * and the mode of operation to clearly distinguish between different outputs.
     *
     * @param transformation the cryptographic transformation used (e.g., "DES/ECB/PKCS5Padding").
     * @return the generated output file name.
     */
    private static String getFileName(String transformation) {
        // Replace slashes ("/") in the transformation with dashes ("-") to create a valid file name.
        return fileNameInputNoExt + "-" +
                transformation.substring(0, transformation.lastIndexOf("/")).replace("/", "-") +
                ".bmp";
    }
}