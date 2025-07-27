package dev.mervick.aesbridge;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;


public class GCM {

    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int TAG_LEN_BIT = 128;
    private static final int KEY_LEN_BIT = 256;
    private static final int PBKDF2_ITER = 100_000;

    private static SecretKey deriveKey(byte[] passphrase, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
            new String(passphrase, StandardCharsets.UTF_8).toCharArray(),
            salt,
            PBKDF2_ITER,
            KEY_LEN_BIT
        );
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Encrypts the given data using AES-GCM and returns the encrypted data as a byte array.
     * The format of the returned byte array is as follows: salt(16) + nonce(12) + ciphertext + tag.
     *
     * @param plaintext the data to encrypt
     * @param passphrase the passphrase to use for encryption
     * @return a byte array containing the encrypted data
     * @throws Exception on encryption error
     */
    public static byte[] encryptBin(Object plaintext, Object passphrase) throws Exception {
        byte[] data = Utils.toBytes(plaintext);
        byte[] passBytes = Utils.toBytes(passphrase);

        byte[] salt = Utils.generateRandom(SALT_LEN);
        byte[] nonce = Utils.generateRandom(NONCE_LEN);

        SecretKey key = deriveKey(passBytes, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LEN_BIT, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] ciphertext = cipher.doFinal(data);

        byte[] encrypted = new byte[SALT_LEN + NONCE_LEN + ciphertext.length];
        System.arraycopy(salt, 0, encrypted, 0, SALT_LEN);
        System.arraycopy(nonce, 0, encrypted, SALT_LEN, NONCE_LEN);
        System.arraycopy(ciphertext, 0, encrypted, SALT_LEN + NONCE_LEN, ciphertext.length);

        return encrypted;
    }

    /**
     * Decrypts the given encrypted data using AES-GCM and returns the decrypted data as a byte array.
     * The format of the given encrypted data is as follows: salt(16) + nonce(12) + ciphertext + tag.
     *
     * @param ciphertext the encrypted data to decrypt
     * @param passphrase the passphrase to use for decryption
     * @return a byte array containing the decrypted data
     * @throws Exception on decryption error
     */
    public static byte[] decryptBin(Object ciphertext, Object passphrase) throws Exception {
        byte[] encrypted = Utils.toBytes(ciphertext);
        byte[] passBytes = Utils.toBytes(passphrase);

        byte[] salt = Arrays.copyOfRange(encrypted, 0, SALT_LEN);
        byte[] nonce = Arrays.copyOfRange(encrypted, SALT_LEN, SALT_LEN + NONCE_LEN);
        byte[] encryptedData = Arrays.copyOfRange(encrypted, SALT_LEN + NONCE_LEN, encrypted.length);

        SecretKey key = deriveKey(passBytes, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LEN_BIT, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(encryptedData);
    }

    /**
     * Encrypts the given string using AES-GCM and encodes the result in Base64.
     * The format of the encrypted data is as follows: salt(16) + nonce(12) + ciphertext + tag.
     *
     * @param plaintext the data to encrypt
     * @param passphrase the passphrase to use for encryption
     * @return a Base64 encoded string containing the encrypted data
     * @throws Exception on encryption error
     */
    public static byte[] encrypt(Object plaintext, Object passphrase) throws Exception {
        byte[] msg = encryptBin(plaintext, passphrase);
        return Utils.toBytes(Base64.getEncoder().encodeToString(msg));
    }

    /**
     * Decrypts the given Base64 encoded string using AES-GCM and returns the decrypted data as a string.
     *
     * The input data is expected to be a Base64 encoded string containing the encrypted data,
     * formatted as follows: salt(16) + nonce(12) + ciphertext + tag.
     *
     * @param ciphertext the Base64 encoded encrypted data to decrypt
     * @param passphrase the passphrase to use for decryption
     * @return a string containing the decrypted data
     * @throws Exception on decryption error
     */
    public static byte[] decrypt(Object ciphertext, Object passphrase) throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(new String(Utils.toBytes(ciphertext)));
        return decryptBin(encrypted, passphrase);
    }
}
