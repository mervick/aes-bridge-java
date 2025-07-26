package dev.mervick.aesbridge;


public class AesBridge {

    /**
     * Encrypts the given plaintext using the specified AES mode and returns the encrypted data as a byte array.
     *
     * The format of the returned byte array depends on the encryption mode used.
     * For GCM, the format is as follows: salt(16) + nonce(12) + ciphertext + tag.
     * For CBC, the format is as follows: salt(16) + iv(16) + ciphertext + tag(32).
     * For LEGACY, the format is as follows: Salted__{salt}{ciphertext}
     *
     * @param plaintext the data to encrypt
     * @param passphrase the passphrase to use for encryption
     * @param mode the AES encryption mode to use (e.g., "GCM", "CBC", "LEGACY")
     * @return a byte array containing the encrypted data
     * @throws Exception on encryption error
     */
    public static byte[] encrypt(byte[] plaintext, byte[] passphrase, String mode) throws Exception {
        AESMode encryptor = AESMode.getMode(mode);
        return encryptor.encrypt(plaintext, passphrase);
    }

    /**
     * Decrypts the given ciphertext using the specified AES mode and returns the decrypted data as a byte array.
     *
     * The input data is expected to be a byte array containing the encrypted data.
     *
     * @param ciphertext the encrypted data to decrypt
     * @param passphrase the passphrase to use for decryption
     * @param mode the AES encryption mode to use (e.g., "GCM", "CBC", "LEGACY")
     * @return a byte array containing the decrypted data
     * @throws Exception on decryption error
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] passphrase, String mode) throws Exception {
        AESMode encryptor = AESMode.getMode(mode);
        return encryptor.decrypt(ciphertext, passphrase);
    }

    /**
     * Encrypts the given data using the AES-GCM algorithm and returns the encrypted data as a byte array.
     *
     * The format of the returned byte array is as follows: salt(16) + nonce(12) + ciphertext + tag.
     *
     * @param plaintext the data to encrypt
     * @param passphrase the passphrase to use for encryption
     * @return a byte array containing the encrypted data
     * @throws Exception on encryption error
     */
    public static byte[] encrypt(byte[] plaintext, byte[] passphrase) throws Exception {
        AESMode encryptor = AESMode.getMode("GCM");
        return encryptor.encrypt(plaintext, passphrase);
    }

    /**
     * Decrypts the given ciphertext using the AES-GCM algorithm and returns the decrypted data as a byte array.
     *
     * The input data is expected to be a byte array containing the encrypted data,
     * formatted as follows: salt(16) + nonce(12) + ciphertext + tag.
     *
     * @param ciphertext the encrypted data to decrypt
     * @param passphrase the passphrase to use for decryption
     * @return a byte array containing the decrypted data
     * @throws Exception on decryption error
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] passphrase) throws Exception {
        AESMode encryptor = AESMode.getMode("GCM");
        return encryptor.decrypt(ciphertext, passphrase);
    }
}
