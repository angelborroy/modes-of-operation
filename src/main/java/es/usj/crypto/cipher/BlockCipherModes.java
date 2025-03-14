package es.usj.crypto.cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class demonstrating different block cipher modes:
 *
 * - ECB (Electronic Codebook)
 * - CBC (Cipher Block Chaining)
 * - CFB (Cipher Feedback)
 * - OFB (Output Feedback)
 * - CTR (Counter)
 *
 * This implementation is simplified and does not address real encryption scenarios.
 * It uses XOR with a basic key for educational purposes.
 */
public class BlockCipherModes {

    // Block size in bytes (8 bytes = 64 bits for this example)
    private static final int BLOCK_SIZE = 8;

    // Cipher key
    private final byte[] key;

    /**
     * Constructor to initialize the key.
     * @param key Encryption key
     */
    public BlockCipherModes(byte[] key) {
        this.key = key;
    }

    /**
     * Encrypts a block using DES (Data Encryption Standard).
     *
     * @param block The block to encrypt (must be 8 bytes long).
     * @return Encrypted block (8 bytes).
     */
    private byte[] encryptBlock(byte[] block) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
            // Using DES with ECB mode and no padding, that is equivalent to "DES"
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(block);
        } catch (Exception e) {
            throw new RuntimeException("Encryption error", e);
        }
    }

    /**
     * Decrypts a block using DES.
     *
     * @param block The block to decrypt (must be 8 bytes long).
     * @return Decrypted block (8 bytes).
     */
    private byte[] decryptBlock(byte[] block) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
            // Using DES with ECB mode and no padding, that is equivalent to "DES"
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(block);
        } catch (Exception e) {
            throw new RuntimeException("Decryption error", e);
        }
    }

    /**
     * Splits a message into fixed-size blocks.
     * Pads the last block with zeros if necessary.
     *
     * @param message The message to split
     * @return 2D Array of blocks
     */
    private byte[][] divideIntoBlocks(byte[] message) {
        int numBlocks = (message.length + BLOCK_SIZE - 1) / BLOCK_SIZE;
        byte[][] blocks = new byte[numBlocks][BLOCK_SIZE];

        for (int i = 0; i < numBlocks; i++) {
            int bytesToCopy = Math.min(BLOCK_SIZE, message.length - i * BLOCK_SIZE);
            System.arraycopy(message, i * BLOCK_SIZE, blocks[i], 0, bytesToCopy);

            // Pad with zeros if the last block is incomplete
            for (int j = bytesToCopy; j < BLOCK_SIZE; j++) {
                blocks[i][j] = 0;
            }
        }
        return blocks;
    }

    /**
     * Combines blocks back into a single message.
     *
     * @param blocks Blocks to combine as 2D Array
     * @param originalLength Original message length
     * @return Combined message
     */
    private byte[] combineBlocks(byte[][] blocks, int originalLength) {
        byte[] result = new byte[originalLength];
        int bytesLeft = originalLength;

        for (int i = 0; i < blocks.length; i++) {
            int bytesToCopy = Math.min(BLOCK_SIZE, bytesLeft);
            System.arraycopy(blocks[i], 0, result, i * BLOCK_SIZE, bytesToCopy);
            bytesLeft -= bytesToCopy;
        }
        return result;
    }

    /**
     * Performs XOR operation between two byte arrays.
     *
     * @param a First byte array
     * @param b Second byte array
     * @return XOR result
     */
    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /**
     * ECB Mode (Electronic Codebook) - Encrypts each block independently.
     */
    public byte[] encryptECB(byte[] message) {
        byte[][] blocks = divideIntoBlocks(message);

        // Encrypt each block

        // Return the full ciphertext (multiple of block size)
        return combineBlocks(blocks, blocks.length * BLOCK_SIZE);
    }

    public byte[] decryptECB(byte[] ciphertext, int originalLength) {
        byte[][] blocks = divideIntoBlocks(ciphertext);

        // Decrypt each block

        // Only return the original message length bytes (exclude padding)
        return combineBlocks(blocks, originalLength);
    }

    /**
     * CBC Mode (Cipher Block Chaining) - Each block depends on the previous one.
     *
     * Plaintext Blocks:   [ P1 ]   [ P2 ]
     *                      |        |
     * IV (Initialization Vector)    |
     *   ↓                           |
     * XOR with IV  ───►  P1 ⊕ IV    |
     *                      |        |
     * Encrypt Block ───►  C1        |
     *                      |        |
     *            XOR with C1 ───►  P2 ⊕ C1
     *                      |
     *            Encrypt Block ───►  C2
     *
     * Ciphertext:        [ C1 ]   [ C2 ]
     */
    public byte[] encryptCBC(byte[] message, byte[] iv) {
        byte[][] blocks = divideIntoBlocks(message);

        // Use IV for first previous block
        // Encrypt each block with previous block:
        //   - XOR(block, previousBlock)
        //   - Encrypt(XOR)

        // Return the full ciphertext (multiple of block size)
        return combineBlocks(blocks, blocks.length * BLOCK_SIZE);
    }

    /**
     * Ciphertext Blocks: [ C1 ]   [ C2 ]
     *                      |        |
     * Decrypt Block ───► D(C1)      |
     *                      |        |
     * XOR with IV  ───► D(C1) ⊕ IV  |
     *                               |
     * Decrypt Block ───► D(C2)      |
     *                      |        |
     *            XOR with C1 ───► D(C2) ⊕ C1
     *
     * Recovered Plaintext: [ P1 ]   [ P2 ]
     */
    public byte[] decryptCBC(byte[] ciphertext, byte[] iv, int originalLength) {
        byte[][] blocks = divideIntoBlocks(ciphertext);

        // Use IV for first previous block
        // Decrypt each block with previous block:
        //   - Decrypt(block)
        //   - XOR(Decrypt, previousBlock)

        // Only return the original message length bytes (exclude padding)
        return combineBlocks(blocks, originalLength);
    }

    /**
     * CFB Mode (Cipher Feedback) - Uses previous encrypted output as input.
     *
     * Plaintext Blocks:   [ P1 ]   [ P2 ]
     *                      |        |
     * IV (Initialization Vector)    |
     *   ↓                           |
     * Encrypt IV  ───►  E(IV)       |
     *                      |        |
     * XOR with P1 ───►  P1 ⊕ E(IV)  |
     *                      |        |
     *               Output C1       |
     *                      |        |
     *    Encrypt C1 ───►  E(C1)     |
     *                      |
     *    XOR with P2 ───► P2 ⊕ E(C1)
     *                      |
     *               Output C2
     *
     * Ciphertext:        [ C1 ]   [ C2 ]
     */
    public byte[] encryptCFB(byte[] message, byte[] iv) {
        byte[][] blocks = divideIntoBlocks(message);

        // Use IV for first previous block
        // Decrypt each block with previous block:
        //   - Encrypt(previousBlock)
        //   - XOR(Encrypt, block)

        return combineBlocks(blocks, message.length);
    }

    /**
     * Ciphertext Blocks: [ C1 ]   [ C2 ]
     *                      |        |
     * Encrypt IV  ───►  E(IV)      |
     *                      |        |
     * XOR with C1 ───► C1 ⊕ E(IV)  |
     *                      |        |
     *               Output P1       |
     *                      |        |
     *    Encrypt C1 ───►  E(C1)     |
     *                      |
     *    XOR with C2 ───► C2 ⊕ E(C1)
     *                      |
     *               Output P2
     *
     * Recovered Plaintext: [ P1 ]   [ P2 ]
     */
    public byte[] decryptCFB(byte[] ciphertext, byte[] iv, int originalLength) {
        byte[][] blocks = divideIntoBlocks(ciphertext);

        // Use IV for first previous block
        // Decrypt each block with previous block:
        //   - Encrypt(previousBlock)
        //   - XOR(Encrypt, block)
        // Note that "decryptBlock" is not required:
        //   CFB mode uses encryptBlock for both encryption and decryption because it turns the cipher into a stream cipher
        //   Instead of decrypting ciphertext blocks, it encrypts the previous ciphertext (or IV) to generate a keystream

        return combineBlocks(blocks, originalLength);
    }

    /**
     * OFB Mode (Output Feedback) - Generates a keystream and XORs it with data.
     *
     * Plaintext Blocks:   [ P1 ]   [ P2 ]
     *                      |        |
     * IV (Initialization Vector)    |
     *   ↓                           |
     * Encrypt IV  ───►  E(IV)  ───► KeyStream1
     *                      |        |
     * XOR with P1 ───►  P1 ⊕ KeyStream1
     *                      |        |
     *               Output C1       |
     *                      |        |
     * Encrypt KeyStream1 ─►  E(KeyStream1)  ─► KeyStream2
     *                      |
     * XOR with P2 ───►  P2 ⊕ KeyStream2
     *                      |
     *               Output C2
     *
     * Ciphertext:        [ C1 ]   [ C2 ]
     */
    public byte[] encryptOFB(byte[] message, byte[] iv) {
        byte[][] blocks = divideIntoBlocks(message);

        // Use IV for first keystream
        // - encrypt(keyStream) to get a new keyStream
        // - XOR(block, keyStream)

        return combineBlocks(blocks, message.length);
    }

    /**
     * Ciphertext Blocks: [ C1 ]   [ C2 ]
     *                      |        |
     * IV (Initialization Vector)    |
     *   ↓                           |
     * Encrypt IV  ───►  E(IV)  ───► KeyStream1
     *                      |        |
     * XOR with C1 ───►  C1 ⊕ KeyStream1
     *                      |        |
     *               Output P1       |
     *                      |        |
     * Encrypt KeyStream1 ─►  E(KeyStream1)  ─► KeyStream2
     *                      |
     * XOR with C2 ───►  C2 ⊕ KeyStream2
     *                      |
     *               Output P2
     *
     * Recovered Plaintext: [ P1 ]   [ P2 ]
     */
    public byte[] decryptOFB(byte[] ciphertext, byte[] iv) {
        return encryptOFB(ciphertext, iv); // OFB decryption is the same as encryption
    }

    /**
     * Increments a byte array (nonce) by a specified value.
     * This method treats the byte array as an unsigned integer in big-endian format
     * (most significant byte first) and adds the specified increment to it.
     *
     * @param nonce The byte array to increment. This array is not modified.
     * @param increment The value to add to the nonce (must be non-negative).
     * @return A new byte array containing the result of adding the increment to the nonce.
     *         The returned array has the same length as the input nonce.
     * @implNote This implementation handles carry propagation from right to left.
     *           If the addition results in an overflow beyond the most significant byte,
     *           the overflow will be lost (the result will wrap around).
     *
     * @example <pre>
     * byte[] nonce = new byte[] {0x00, 0x01, 0x02, 0x03};
     * byte[] result = incrementNonce(nonce, 5);
     * // result will be {0x00, 0x01, 0x02, 0x08}
     * </pre>
     */
    public byte[] incrementNonce(byte[] nonce, int increment) {
        // Create a copy of the original nonce
        byte[] result = nonce.clone();

        // Add the increment to the least significant byte and handle carry
        int carry = increment;
        for (int i = result.length - 1; i >= 0 && carry > 0; i--) {
            // Convert to int to avoid overflow issues during addition
            int sum = (result[i] & 0xFF) + carry;
            // Store the lower 8 bits of the sum
            result[i] = (byte)(sum & 0xFF);
            // Calculate the carry for the next iteration
            carry = sum >>> 8;
        }

        return result;
    }

    /**
     * CTR Mode (Counter) - Encrypts incremented counter values and XORs with data.
     *
     * Plaintext Blocks:   [ P1 ]   [ P2 ]
     *                      |        |
     * Counter 1 (Nonce || 0001)    |
     *   ↓                           |
     * Encrypt Counter 1 ─►  E(N || 0001)  ─► KeyStream1
     *                      |        |
     * XOR with P1 ───►  P1 ⊕ KeyStream1
     *                      |        |
     *               Output C1       |
     *                      |        |
     * Counter 2 (Nonce || 0002)    |
     *   ↓
     * Encrypt Counter 2 ─►  E(N || 0002)  ─► KeyStream2
     *                      |
     * XOR with P2 ───►  P2 ⊕ KeyStream2
     *                      |
     *               Output C2
     *
     * Ciphertext:        [ C1 ]   [ C2 ]
     */
    public byte[] encryptCTR(byte[] message, byte[] nonce) {
        byte[][] blocks = divideIntoBlocks(message);

        // Initialize Counter to Nonce value
        // Add Block Number to Counter using incrementNonce method
        // - Encrypt(counter)
        // - XOR(block, Encrypt)

        return combineBlocks(blocks, message.length);
    }

    /**
     * Ciphertext Blocks: [ C1 ]   [ C2 ]
     *                      |        |
     * Counter 1 (Nonce || 0001)    |
     *   ↓                           |
     * Encrypt Counter 1 ─►  E(N || 0001)  ─► KeyStream1
     *                      |        |
     * XOR with C1 ───►  C1 ⊕ KeyStream1
     *                      |        |
     *               Output P1       |
     *                      |        |
     * Counter 2 (Nonce || 0002)    |
     *   ↓
     * Encrypt Counter 2 ─►  E(N || 0002)  ─► KeyStream2
     *                      |
     * XOR with C2 ───►  C2 ⊕ KeyStream2
     *                      |
     *               Output P2
     *
     * Recovered Plaintext: [ P1 ]   [ P2 ]
     */
    public byte[] decryptCTR(byte[] ciphertext, byte[] nonce) {
        return encryptCTR(ciphertext, nonce); // CTR decryption is the same as encryption
    }

    public static void main(String[] args) {

        // Test your implementation

    }

}
