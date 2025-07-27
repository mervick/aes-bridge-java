package dev.mervick.aesbridge;

public enum AESMode {
    CBC {
        @Override
        public byte[] encrypt(Object plaintext, Object passphrase) throws Exception {
            return dev.mervick.aesbridge.CBC.encrypt(plaintext, passphrase);
        }

        @Override
        public byte[] decrypt(Object ciphertext, Object passphrase) throws Exception {
            return dev.mervick.aesbridge.CBC.decrypt(ciphertext, passphrase);
        }
    },
    GCM {
        @Override
        public byte[] encrypt(Object plaintext, Object passphrase) throws Exception {
            return dev.mervick.aesbridge.GCM.encrypt(plaintext, passphrase);
        }

        @Override
        public byte[] decrypt(Object ciphertext, Object passphrase) throws Exception {
            return dev.mervick.aesbridge.GCM.decrypt(ciphertext, passphrase);
        }
    },
    LEGACY {
        @Override
        public byte[] encrypt(Object plaintext, Object passphrase) throws Exception {
            return dev.mervick.aesbridge.Legacy.encrypt(plaintext, passphrase);
        }

        @Override
        public byte[] decrypt(Object ciphertext, Object passphrase) throws Exception {
            return dev.mervick.aesbridge.Legacy.decrypt(ciphertext, passphrase);
        }
    };

    public abstract byte[] encrypt(Object plaintext, Object passphrase) throws Exception;
    public abstract byte[] decrypt(Object ciphertext, Object passphrase) throws Exception;

    public static AESMode getMode(String modeName) {
        try {
            return AESMode.valueOf(modeName.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown AES mode: " + modeName);
        }
    }
}
