package dev.mervick.aesbridge;

// import dev.mervick.aesbridge.CBC;
// import dev.mervick.aesbridge.GCM;
// import dev.mervick.aesbridge.Legacy;

import java.util.stream.Stream;
import java.util.stream.IntStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
import org.json.JSONArray;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.*;
import org.junit.jupiter.params.provider.*;

import java.io.*;

import static org.junit.jupiter.api.Assertions.*;

class AesBridgeTest {

    static JSONObject testData;

    @BeforeAll
    static void loadTestData() throws Exception {
        InputStream is = AesBridgeTest.class.getResourceAsStream("/test_data.json");
        if (is == null) {
            throw new FileNotFoundException("Resource file /test_data.json not found");
        }
        String json = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        testData = new JSONObject(json).getJSONObject("testdata");
    }

    // ========== CBC ==========
    @ParameterizedTest(name = "CBC: plaintext encrypt/decrypt {0}")
    @MethodSource("plaintextProvider")
    void testCbcEncryptDecrypt(String input) throws Exception {
        byte[] data = input.getBytes("UTF-8");
        byte[] encrypted = CBC.encrypt(data, data);
        byte[] decrypted = CBC.decrypt(encrypted, data);
        assertArrayEquals(data, decrypted, "CBC encryption/decryption failed");
    }

    @ParameterizedTest(name = "CBC: hex encrypt/decrypt {0}")
    @MethodSource("hexProvider")
    void testCbcHexEncryptDecrypt(String hex) throws Exception {
        byte[] data = hexStringToByteArray(hex);
        byte[] encrypted = CBC.encrypt(data, data);
        byte[] decrypted = CBC.decrypt(encrypted, data);
        assertArrayEquals(data, decrypted, "CBC hex encryption/decryption failed");
    }

    @ParameterizedTest(name = "CBC: plaintext encrypt/decrypt {0}")
    @MethodSource("plaintextProvider")
    void testAesBridgeCbcEncryptDecrypt(String input) throws Exception {
        byte[] data = input.getBytes("UTF-8");
        byte[] encrypted = AesBridge.encrypt(data, data, "CBC");
        byte[] decrypted = AesBridge.decrypt(encrypted, data, "CBC");
        assertArrayEquals(data, decrypted, "CBC encryption/decryption failed");
    }

    @ParameterizedTest(name = "CBC: hex encrypt/decrypt {0}")
    @MethodSource("hexProvider")
    void testAesBridgeCbcHexEncryptDecrypt(String hex) throws Exception {
        byte[] data = hexStringToByteArray(hex);
        byte[] encrypted = AesBridge.encrypt(data, data, "CBC");
        byte[] decrypted = AesBridge.decrypt(encrypted, data, "CBC");
        assertArrayEquals(data, decrypted, "CBC hex encryption/decryption failed");
    }

    // ========== GCM ==========
    @ParameterizedTest(name = "GCM: plaintext encrypt/decrypt {0}")
    @MethodSource("plaintextProvider")
    void testGcmEncryptDecrypt(String input) throws Exception {
        byte[] data = input.getBytes("UTF-8");
        byte[] encrypted = GCM.encrypt(data, data);
        byte[] decrypted = GCM.decrypt(encrypted, data);
        assertArrayEquals(data, decrypted, "GCM encryption/decryption failed");
    }

    @ParameterizedTest(name = "GCM: hex encrypt/decrypt {0}")
    @MethodSource("hexProvider")
    void testGcmHexEncryptDecrypt(String hex) throws Exception {
        byte[] data = hexStringToByteArray(hex);
        byte[] encrypted = GCM.encrypt(data, data);
        byte[] decrypted = GCM.decrypt(encrypted, data);
        assertArrayEquals(data, decrypted, "GCM hex encryption/decryption failed");
    }
    @ParameterizedTest(name = "GCM: plaintext encrypt/decrypt {0}")
    @MethodSource("plaintextProvider")
    void testAesBridgeGcmEncryptDecrypt(String input) throws Exception {
        byte[] data = input.getBytes("UTF-8");
        byte[] encrypted = AesBridge.encrypt(data, data);
        byte[] decrypted = AesBridge.decrypt(encrypted, data);
        assertArrayEquals(data, decrypted, "GCM encryption/decryption failed");

        byte[] encrypted1 = AesBridge.encrypt(data, data, "GCM");
        byte[] decrypted2 = AesBridge.decrypt(encrypted1, data, "GCM");
        assertArrayEquals(data, decrypted2, "GCM encryption/decryption failed");
    }

    @ParameterizedTest(name = "GCM: hex encrypt/decrypt {0}")
    @MethodSource("hexProvider")
    void testAesBridgeGcmHexEncryptDecrypt(String hex) throws Exception {
        byte[] data = hexStringToByteArray(hex);
        byte[] encrypted = AesBridge.encrypt(data, data);
        byte[] decrypted = AesBridge.decrypt(encrypted, data);
        assertArrayEquals(data, decrypted, "GCM hex encryption/decryption failed");

        byte[] encrypted1 = AesBridge.encrypt(data, data, "GCM");
        byte[] decrypted1 = AesBridge.decrypt(encrypted1, data, "GCM");
        assertArrayEquals(data, decrypted1, "GCM hex encryption/decryption failed");
    }

    // ========== Legacy ==========
    @ParameterizedTest(name = "Legacy: plaintext encrypt/decrypt {0}")
    @MethodSource("plaintextProvider")
    void testLegacyEncryptDecrypt(String input) throws Exception {
        byte[] data = input.getBytes("UTF-8");
        byte[] encrypted = Legacy.encrypt(data, data);
        byte[] decrypted = Legacy.decrypt(encrypted, data);
        assertArrayEquals(data, decrypted, "Legacy encryption/decryption failed");
    }

    @ParameterizedTest(name = "Legacy: hex encrypt/decrypt {0}")
    @MethodSource("hexProvider")
    void testLegacyHexEncryptDecrypt(String hex) throws Exception {
        byte[] data = hexStringToByteArray(hex);
        byte[] encrypted = Legacy.encrypt(data, data);
        byte[] decrypted = Legacy.decrypt(encrypted, data);
        assertArrayEquals(data, decrypted, "Legacy hex encryption/decryption failed");
    }

    @ParameterizedTest(name = "Legacy: plaintext encrypt/decrypt {0}")
    @MethodSource("plaintextProvider")
    void testAesBridgeLegacyEncryptDecrypt(String input) throws Exception {
        byte[] data = input.getBytes("UTF-8");
        byte[] encrypted = AesBridge.encrypt(data, data, "Legacy");
        byte[] decrypted = AesBridge.decrypt(encrypted, data, "Legacy");
        assertArrayEquals(data, decrypted, "Legacy encryption/decryption failed");
    }

    @ParameterizedTest(name = "Legacy: hex encrypt/decrypt {0}")
    @MethodSource("hexProvider")
    void testAesBridgeLegacyHexEncryptDecrypt(String hex) throws Exception {
        byte[] data = hexStringToByteArray(hex);
        byte[] encrypted = AesBridge.encrypt(data, data, "Legacy");
        byte[] decrypted = AesBridge.decrypt(encrypted, data, "Legacy");
        assertArrayEquals(data, decrypted, "Legacy hex encryption/decryption failed");
    }

    // ========== Dynamic tests ==========
    @ParameterizedTest(name = "CBC: decrypt test {0}")
    @MethodSource("decryptCbcProvider")
    void testCbcDecrypt(String encrypted, String passphrase, byte[] expected) throws Exception {
        byte[] decrypted = CBC.decrypt(encrypted.getBytes("UTF-8"), passphrase.getBytes("UTF-8"));
        assertArrayEquals(expected, decrypted, "CBC decrypt failed");
        byte[] decrypted1 = AesBridge.decrypt(encrypted.getBytes("UTF-8"), passphrase.getBytes("UTF-8"), "CBC");
        assertArrayEquals(expected, decrypted1, "CBC decrypt failed");
    }

    @ParameterizedTest(name = "GCM: decrypt test {0}")
    @MethodSource("decryptGcmProvider")
    void testGcmDecrypt(String encrypted, String passphrase, byte[] expected) throws Exception {
        byte[] decrypted = GCM.decrypt(encrypted.getBytes("UTF-8"), passphrase.getBytes("UTF-8"));
        assertArrayEquals(expected, decrypted, "GCM decrypt failed");
        byte[] decrypted1 = AesBridge.decrypt(encrypted.getBytes("UTF-8"), passphrase.getBytes("UTF-8"), "GCM");
        assertArrayEquals(expected, decrypted1, "GCM decrypt failed");
    }

    @ParameterizedTest(name = "Legacy: decrypt test {0}")
    @MethodSource("decryptLegacyProvider")
    void testLegacyDecrypt(String encrypted, String passphrase, byte[] expected) throws Exception {
        byte[] decrypted = Legacy.decrypt(encrypted.getBytes("UTF-8"), passphrase.getBytes("UTF-8"));
        assertArrayEquals(expected, decrypted, "Legacy decrypt failed");
        byte[] decrypted1 = AesBridge.decrypt(encrypted.getBytes("UTF-8"), passphrase.getBytes("UTF-8"), "Legacy");
        assertArrayEquals(expected, decrypted1, "Legacy decrypt failed");
    }

    // ================== Providers for parameterized tests ==================
    static Stream<Arguments> plaintextProvider() {
        JSONArray arr = testData.getJSONArray("plaintext");
        return IntStream.range(0, arr.length())
                .mapToObj(i -> Arguments.of(arr.getString(i)));
    }

    static Stream<Arguments> hexProvider() {
        JSONArray arr = testData.getJSONArray("hex");
        return IntStream.range(0, arr.length())
                .mapToObj(i -> Arguments.of(arr.getString(i)));
    }

    static Stream<Arguments> decryptCbcProvider() throws IOException {
        return decryptProvider("encrypted-cbc");
    }

    static Stream<Arguments> decryptGcmProvider() throws IOException {
        return decryptProvider("encrypted-gcm");
    }

    static Stream<Arguments> decryptLegacyProvider() throws IOException {
        return decryptProvider("encrypted-legacy");
    }

    static Stream<Arguments> decryptProvider(String field) throws IOException {
        InputStream is = AesBridgeTest.class.getResourceAsStream("/test_data.json");
        if (is == null) {
            throw new FileNotFoundException("Resource file /test_data.json not found");
        }
        String json = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        JSONArray arr = new JSONObject(json).getJSONArray("decrypt");

        return IntStream.range(0, arr.length())
                .filter(i -> arr.getJSONObject(i).has(field))
                .mapToObj(i -> {
                    JSONObject obj = arr.getJSONObject(i);
                    byte[] expected = obj.has("plaintext") ?
                        obj.getString("plaintext").getBytes(StandardCharsets.UTF_8)
                        : hexStringToByteArray(obj.getString("hex"));
                    return Arguments.of(obj.getString(field), obj.getString("passphrase"), expected);
                });
    }

    // ================== Additional helper methods ==================
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
