package dev.mervick.aesbridge;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;


public class Legacy {

    private static final int KEY_LEN = 32;
    private static final int IV_LEN = 16;
    private static final int SALT_LEN = 8;
    private static final String SALTED_MAGIC = "Salted__";

    private static class KeyIv {
        final byte[] key;
        final byte[] iv;

        KeyIv(byte[] key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }
    }

    private static KeyIv deriveKeyAndIv(byte[] password, byte[] salt) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] d = new byte[0];
        byte[] di = new byte[0];
        int requiredLength = KEY_LEN + IV_LEN;
        while (d.length < requiredLength) {
            md5.reset();
            md5.update(di);
            md5.update(password);
            md5.update(salt);
            di = md5.digest();
            d = Utils.concat(d, di);
        }
        byte[] key = Arrays.copyOfRange(d, 0, KEY_LEN);
        byte[] iv = Arrays.copyOfRange(d, KEY_LEN, KEY_LEN + IV_LEN);
        return new KeyIv(key, iv);
    }

    /**
     * Encrypts the given data using the legacy OpenSSL-compatible key derivation
     * algorithm, and returns the encrypted data as a Base64 string.
     *
     * The format of the returned Base64 string is as follows: Salted__{salt}{ciphertext}
     * This format is compatible with OpenSSL's {@code enc} command.
     *
     * @param data the data to encrypt
     * @param passphrase the passphrase to use for encryption
     * @return a Base64 string containing the encrypted data
     * @throws Exception on error
     */
    public static byte[] encrypt(Object data, Object passphrase) throws Exception {
        byte[] plaintext = Utils.toBytes(data);
        byte[] password = Utils.toBytes(passphrase);
        byte[] salt = Utils.generateRandom(SALT_LEN);
        KeyIv keyIv = deriveKeyAndIv(password, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(keyIv.key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(keyIv.iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] result = Utils.concat(
                SALTED_MAGIC.getBytes(StandardCharsets.US_ASCII),
                Utils.concat(salt, ciphertext)
        );

        return Base64.getEncoder().encode(result);
    }

    /**
     * Decrypts the given ciphertext using the legacy OpenSSL-compatible key derivation
     * algorithm, and returns the decrypted data as a byte array.
     *
     * The input data is expected to be a Base64 string containing the ciphertext,
     * formatted as follows: Salted__{salt}{ciphertext}
     *
     * This format is compatible with OpenSSL's {@code enc} command.
     * @param data the ciphertext to decrypt
     * @param passphrase the passphrase to use for decryption
     * @return a byte array containing the decrypted data
     * @throws Exception on error
     */
    public static byte[] decrypt(Object data, Object passphrase) throws Exception {
        byte[] cipherData = Base64.getDecoder().decode(Utils.toBytes(data));
        if (cipherData.length < SALTED_MAGIC.length() + SALT_LEN) {
            throw new IllegalArgumentException("Ciphertext too short");
        }
        byte[] magicBytes = Arrays.copyOfRange(cipherData, 0, SALTED_MAGIC.length());
        if (!Arrays.equals(magicBytes, SALTED_MAGIC.getBytes(StandardCharsets.US_ASCII))) {
            return new byte[0];
        }
        byte[] salt = Arrays.copyOfRange(cipherData, SALTED_MAGIC.length(), SALTED_MAGIC.length() + SALT_LEN);
        byte[] ciphertext = Arrays.copyOfRange(cipherData, SALTED_MAGIC.length() + SALT_LEN, cipherData.length);

        byte[] password = Utils.toBytes(passphrase);
        KeyIv keyIv = deriveKeyAndIv(password, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(keyIv.key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(keyIv.iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(ciphertext);
    }
}
