package dev.mervick.aesbridge;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;


public class CBC {

    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 16;
    private static final int KEY_LEN = 32; // 256 bits
    private static final int MAC_LEN = 32; // SHA-256 HMAC
    private static final int PBKDF2_ITER = 100_000;

    private static class KeyTuple {
        final byte[] aesKey;
        final byte[] hmacKey;
        KeyTuple(byte[] aesKey, byte[] hmacKey) {
            this.aesKey = aesKey;
            this.hmacKey = hmacKey;
        }
    }

    private static KeyTuple deriveKeys(byte[] passphrase, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
            new String(passphrase, StandardCharsets.UTF_8).toCharArray(),
            salt,
            PBKDF2_ITER,
            (KEY_LEN + MAC_LEN) * 8
        );
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyMaterial = skf.generateSecret(spec).getEncoded();
        byte[] aesKey = Arrays.copyOfRange(keyMaterial, 0, KEY_LEN);
        byte[] hmacKey = Arrays.copyOfRange(keyMaterial, KEY_LEN, KEY_LEN + KEY_LEN);
        return new KeyTuple(aesKey, hmacKey);
    }

    /**
     * Encrypts the given data using the AES-CBC + HMAC algorithm, and returns the encrypted data as a raw byte array.
     *
     * The format of the returned byte array is as follows: salt(16) + iv(16) + ciphertext + tag(32)
     *
     * @param plaintext the data to encrypt
     * @param passphrase the passphrase to use for encryption
     * @return a byte array containing the encrypted data
     * @throws Exception on error
     */
    public static byte[] encryptBin(Object plaintext, Object passphrase) throws Exception {
        byte[] plain = Utils.toBytes(plaintext);
        byte[] passBytes = Utils.toBytes(passphrase);

        byte[] salt = Utils.generateRandom(SALT_LEN);
        byte[] iv = Utils.generateRandom(IV_LEN);

        KeyTuple keys = deriveKeys(passBytes, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keys.aesKey, "AES"), new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plain);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(keys.hmacKey, "HmacSHA256"));
        mac.update(iv);
        mac.update(ciphertext);
        byte[] tag = mac.doFinal();

        ByteBuffer buf = ByteBuffer.allocate(salt.length + iv.length + ciphertext.length + tag.length);
        buf.put(salt).put(iv).put(ciphertext).put(tag);
        return buf.array();
    }

    /**
     * Decrypts the given encrypted data using the AES-CBC + HMAC algorithm, and returns the decrypted data as a raw byte array.
     *
     * The format of the given encrypted data is as follows: salt(16) + iv(16) + ciphertext + tag(32)
     *
     * @param ciphertext the encrypted data to decrypt
     * @param passphrase the passphrase to use for decryption
     * @return a byte array containing the decrypted data
     * @throws Exception on error
     */
    public static byte[] decryptBin(Object ciphertext, Object passphrase) throws Exception {
        byte[] enc = Utils.toBytes(ciphertext);
        byte[] passBytes = Utils.toBytes(passphrase);

        byte[] salt = Arrays.copyOfRange(enc, 0, SALT_LEN);
        byte[] iv = Arrays.copyOfRange(enc, SALT_LEN, SALT_LEN + IV_LEN);
        byte[] tag = Arrays.copyOfRange(enc, enc.length - MAC_LEN, enc.length);
        byte[] data = Arrays.copyOfRange(enc, SALT_LEN + IV_LEN, enc.length - MAC_LEN);

        KeyTuple keys = deriveKeys(passBytes, salt);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(keys.hmacKey, "HmacSHA256"));
        mac.update(iv);
        mac.update(data);
        byte[] expectedTag = mac.doFinal();

        if (!Arrays.equals(expectedTag, tag)) {
            throw new SecurityException("HMAC validation failed");
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keys.aesKey, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    /**
     * Encrypts the given data using the AES-CBC + HMAC algorithm and encodes the result in Base64.
     *
     * The format of the Base64 encoded string is as follows: salt(16) + iv(16) + ciphertext + tag(32).
     *
     * @param plaintext the data to encrypt
     * @param passphrase the passphrase to use for encryption
     * @return a byte array containing the Base64 encoded encrypted data
     * @throws Exception on error
     */
    public static byte[] encrypt(Object plaintext, Object passphrase) throws Exception {
        byte[] msg = encryptBin(plaintext, passphrase);
        return Utils.toBytes(Base64.getEncoder().encodeToString(msg));
    }

    /**
     * Decrypts the given Base64 encoded string using the AES-CBC + HMAC algorithm, and returns the decrypted data as a raw byte array.
     *
     * The format of the given Base64 encoded string is as follows: salt(16) + iv(16) + ciphertext + tag(32)
     *
     * @param ciphertext the Base64 encoded string to decrypt
     * @param passphrase the passphrase to use for decryption
     * @return a byte array containing the decrypted data
     * @throws Exception on error
     */
    public static byte[] decrypt(Object ciphertext, Object passphrase) throws Exception {
        byte[] data = Base64.getDecoder().decode(Utils.toBytes(ciphertext));
        return decryptBin(data, passphrase);
    }

    public static void main(String[] args) {
        try {
            byte[] data = "Hello, world!".getBytes(StandardCharsets.UTF_8);
            byte[] enc = encrypt(data, "my-secret-passphrase".getBytes(StandardCharsets.UTF_8));
            byte[] dec = decrypt(enc, "my-secret-passphrase".getBytes(StandardCharsets.UTF_8));
            System.out.println("Encrypted: " + new String(enc, StandardCharsets.UTF_8));
            System.out.println("Decrypted: " + new String(dec, StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
