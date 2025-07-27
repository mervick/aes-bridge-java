package dev.mervick.aesbridge;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

class Utils {
    public static byte[] generateRandom(int size) {
        byte[] buf = new byte[size];
        new SecureRandom().nextBytes(buf);
        return buf;
    }

    public static byte[] toBytes(Object data) {
        if (data instanceof byte[]) {
            return (byte[]) data;
        } else if (data instanceof String) {
            return ((String) data).getBytes(StandardCharsets.UTF_8);
        }
        throw new IllegalArgumentException("Unsupported data type");
    }

    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] base64UrlDecode(String data) {
        return Base64.getUrlDecoder().decode(data);
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
