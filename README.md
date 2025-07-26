# AesBridge Java

![CI Status](https://github.com/mervick/aes-bridge-java/actions/workflows/tests.yml/badge.svg)

**AesBridge** is a modern, secure, and cross-language **AES** encryption library. It offers a unified interface for encrypting and decrypting data across multiple programming languages. Supports **GCM**, **CBC**, and **legacy AES Everywhere** modes.

This is the **Java implementation** of the core project.  
👉 Main repository: https://github.com/mervick/aes-bridge


## Features

- **🛡️ AES-256 encryption** - Industry-standard 256-bit encryption
- **🔐 Multiple modes** - **GCM** (recommended) and **CBC with HMAC**
- **↩️ Legacy CBC** - For backward compatibility with projects using **AES Everywhere** (legacy OpenSSL-compatible mode).
- **🌍 Cross-language compatibility** - Unified implementation across languages
- **✨ Secure by design** - Proper key derivation and cryptographic best practices

## Usage

The main class `AesBridge` exposes convenient static methods to encrypt and decrypt data:

```java
import dev.mervick.aesbridge.AesBridge;
// import dev.mervick.aesbridge.CBC;
// import dev.mervick.aesbridge.GCM;
// import dev.mervick.aesbridge.Legacy;

public class Example {
    public static void main(String[] args) throws Exception {
        String message = "My secret message";
        String passphrase = "MyStrongPass";

        byte[] plaintext = message.getBytes("UTF-8");
        byte[] passBytes = passphrase.getBytes("UTF-8");

        // Encrypt using the default GCM mode
        byte[] encrypted = AesBridge.encrypt(plaintext, passBytes);
        // Decrypt using the default GCM mode
        byte[] decrypted = AesBridge.decrypt(encrypted, passBytes);
        System.out.println("Decrypted: " + new String(decrypted, "UTF-8"));

        // Encrypt using CBC mode
        byte[] encryptedCBC = AesBridge.encrypt(plaintext, passBytes, "CBC");
        // Decrypt using CBC mode
        byte[] decryptedCBC = AesBridge.decrypt(encryptedCBC, passBytes, "CBC");
        System.out.println("Decrypted CBC: " + new String(decryptedCBC, "UTF-8"));

        // Encrypt using legacy OpenSSL-compatible mode
        byte[] encryptedLegacy = AesBridge.encrypt(plaintext, passBytes, "LEGACY");
        // Decrypt using legacy mode
        byte[] decryptedLegacy = AesBridge.decrypt(encryptedLegacy, passBytes, "LEGACY");

        System.out.println("Decrypted Legacy: " + new String(decryptedLegacy, "UTF-8"));
    }
}
```

## API Reference

### Main Encryption/Decryption Methods

`dev.mervick.aesbridge.AesBridge`  

#### `byte[] AesBridge.encrypt(byte[] plaintext, byte[] passphrase)`

Encrypts the given plaintext using AES-256-GCM mode (default) with the provided passphrase.  

- **Parameters:**  
  - `plaintext` — the data to encrypt (byte array)  
  - `passphrase` — the secret key passphrase (byte array)
- **Returns:** Encrypted data in raw binary format following the structure above.
- **Throws:** Exceptions on encryption failure.

#### `byte[] AesBridge.decrypt(byte[] ciphertext, byte[] passphrase)`

Decrypts data encrypted with `AesBridge.encrypt()` using AES-256-GCM.  

- **Parameters:**  
  - `ciphertext` — the encrypted data in the binary format described above  
  - `passphrase` — the secret key passphrase used for encryption
- **Returns:**  Decrypted plaintext as a byte array.
- **Throws:** Exceptions on decryption or authentication failure.

#### `byte[] AesBridge.encrypt(byte[] plaintext, byte[] passphrase, String mode)`

Encrypts data with the specified AES mode. Supported modes:
- `"GCM"` — AES-GCM 256-bit encryption.
- `"CBC"` — AES-CBC 256-bit encryption with HMAC-SHA256 authentication.
- `"LEGACY"` — Legacy AES-CBC encryption compatible with OpenSSL `enc` command.

- **Parameters:**  
  - `plaintext` — data to encrypt (byte array)  
  - `passphrase` — secret passphrase (byte array)  
  - `mode` — one of `"GCM"`, `"CBC"`, or `"LEGACY"`
- **Returns:** Encrypted data as a byte array.
- **Throws:**  Exceptions on encryption failure or invalid mode.

#### `byte[] AesBridge.decrypt(byte[] ciphertext, byte[] passphrase, String mode)`

Decrypts data using the specified AES mode. Input format must match the output format of the corresponding `encrypt` method.

- **Parameters:**  
  - `ciphertext` — encrypted data (byte array)  
  - `passphrase` — secret passphrase (byte array)  
  - `mode` — one of `"GCM"`, `"CBC"`, or `"LEGACY"`
- **Returns:** Decrypted plaintext as a byte array.
- **Throws:** Exceptions on decryption failure, authentication failure, or invalid mode.

### Mode-Specific Encryption Methods


### GCM Mode API

`dev.mervick.aesbridge.GCM`  
The GCM mode is the recommended AES encryption mode providing authenticated encryption with associated data using AES-256-GCM.  


#### `public static byte[] GCM.encrypt(Object plaintext, Object passphrase)`

Encrypts the given plaintext with AES-256-GCM and returns Base64 encoded data. The encrypted format is:  
  `salt(16) + nonce(12) + ciphertext + tag(16)`  

- **Parameters:**  
  - `plaintext` — Data to encrypt.  
  - `passphrase` — Encryption passphrase.  
- **Returns:** Base64-encoded byte array containing the encrypted data.
- **Throws:** `Exception` on encryption errors.

#### `public static byte[] GCM.decrypt(Object ciphertext, Object passphrase)`

Decrypts Base64-encoded data encrypted with `encrypt()`. Checks authenticity using GCM's built-in tag.

- **Parameters:**  
  - `ciphertext` — Base64 encoded encrypted data.  
  - `passphrase` — Passphrase for decryption.  
- **Returns:** Decrypted plaintext bytes.
- **Throws:** `Exception` on decryption or authentication failures.

#### `public static byte[] GCM.encryptBin(Object plaintext, Object passphrase)`

Encrypts data using AES-GCM and returns raw binary output without Base64 encoding.

- **Parameters:**  
  - `plaintext` — Data to encrypt.  
  - `passphrase` — Passphrase for encryption.  
- **Returns:** Raw binary encrypted data: `salt(16) + nonce(12) + ciphertext + tag(16)`
- **Throws:** `Exception` on encryption errors.

#### `public static byte[] GCM.decryptBin(Object ciphertext, Object passphrase)`

Decrypts raw binary encrypted data produced by `encryptBin()`. Verifies authentication tag.

- **Parameters:**  
  - `ciphertext` — Raw binary encrypted data.  
  - `passphrase` — Decryption passphrase.  
- **Returns:** Decrypted plaintext bytes.
- **Throws:**  `Exception` on decryption or authentication errors.


### CBC Mode API

`dev.mervick.aesbridge.CBC`  
The CBC mode in AesBridge provides AES-256-CBC encryption combined with HMAC-SHA256 authentication for data integrity, with PBKDF2 key derivation.

#### `public static byte[] CBC.encrypt(Object plaintext, Object passphrase)`

Encrypts the given plaintext using AES-256-CBC with PKCS5 padding and calculates an HMAC-SHA256 tag for integrity. Returns the output as Base64-encoded binary data with the format:  
  `salt(16) + iv(16) + ciphertext + HMAC(32)`  

- **Parameters:**  
  - `plaintext` — The data to encrypt (can be `byte[]`, `String`, or any object convertible to bytes).  
  - `passphrase` — The secret passphrase for encryption (same flexibility as plaintext).  
- **Returns:** Byte array containing the Base64-encoded encrypted result.
- **Throws:** `Exception` on encryption errors.

#### `public static byte[] CBC.decrypt(Object ciphertext, Object passphrase)`

Decrypts data previously encrypted with `encrypt()`. Verifies the HMAC tag to ensure data integrity and authenticity. Input must be Base64-encoded and must follow the format described above.

- **Parameters:**  
  - `ciphertext` — Base64-encoded encrypted data.  
  - `passphrase` — The secret passphrase used for decryption.  
- **Returns:** Byte array of the decrypted plaintext data.
- **Throws:** `SecurityException` if HMAC verification fails, or other exceptions on decryption errors.

#### `public static byte[] CBC.encryptBin(Object plaintext, Object passphrase)`

Encrypts the given data using AES-256-CBC with HMAC-SHA256, returning raw binary data without Base64 encoding.

- **Parameters:**  
  - `plaintext` — The data to encrypt.  
  - `passphrase` — The encryption passphrase.  
- **Returns:** Raw binary encrypted data: `salt(16) + iv(16) + ciphertext + HMAC(32)`
- **Throws:** `Exception` on encryption errors.

#### `public static byte[] CBC.decryptBin(Object ciphertext, Object passphrase)`

Decrypts raw binary encrypted data generated by `encryptBin()`. Verifies HMAC before decryption.

- **Parameters:**  
  - `ciphertext` — Raw binary encrypted data.  
  - `passphrase` — The passphrase for decryption.  
- **Returns:** Raw decrypted data.
- **Throws:** `SecurityException` if HMAC validation fails, or other exceptions on error.


### Legacy Mode API

`dev.mervick.aesbridge.Legacy`  

> ⚠️ These functions are maintained solely for **backward compatibility** with older systems. While they remain fully compatible with the legacy **AES Everywhere** implementation, their use is strongly discouraged in new applications due to potential security limitations compared to GCM or CBC with HMAC.

#### `public static byte[] Legacy.encrypt(Object data, Object passphrase)`

Encrypts data using OpenSSL-compatible legacy AES-256-CBC with an ASCII `"Salted__"` header and salt. Outputs Base64 encoded encrypted data.

- **Parameters:**  
  - `data` — Data to encrypt.  
  - `passphrase` — Encryption passphrase.  
- **Returns:** Base64-encoded byte array containing encrypted data.
- **Throws:** `Exception` on encryption errors.

#### `public static byte[] Legacy.decrypt(Object data, Object passphrase)`

Decrypts Base64-encoded data encrypted with the legacy `encrypt()`. Expects the `"Salted__"` header in input.

- **Parameters:**  
  - `data` — Base64 encoded encrypted data.  
  - `passphrase` — Passphrase used for encryption.  
- **Returns:** Decrypted plaintext bytes.
- **Throws:** `IllegalArgumentException` if input format is incorrect, and other exceptions on decryption errors.


## Modes Details

### AES-GCM (Recommended)

- Encrypts with AES-256-GSM using PKCS#5 padding.
- Strong authenticated encryption with nonce and tag integrity.
- Uses PBKDF2 key derivation with 100,000 iterations.
- Output format binary: `salt(16) + nonce(12) + ciphertext + tag`.
- Output format base64: `base64(salt(16) + nonce(12) + ciphertext + tag(16))`.

### AES-CBC + HMAC-SHA256

- Encrypts with AES-256-CBC using PKCS#5 padding.
- Adds HMAC-SHA256 for authentication (verify data integrity and authenticity).
- Uses PBKDF2 key derivation with 100,000 iterations.
- Output format binary: `salt(16) + IV(16) + ciphertext + HMAC(32)`.
- Output format base64: `base64(salt(16) + IV(16) + ciphertext + HMAC(32))`.

### Legacy AES Everywhere

- Compatible with the OpenSSL command-line `enc` format.
- Uses OpenSSL's EVP_BytesToKey key derivation based on MD5.
- Output format: Base64 string containing `Base64("Salted__" + salt(16) + ciphertext)`.
- **Not recommended for new applications due to weaker security properties**.

