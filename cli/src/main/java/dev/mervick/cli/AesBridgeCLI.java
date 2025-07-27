package dev.mervick.cli;

import dev.mervick.aesbridge.AesBridge;

import java.nio.charset.StandardCharsets;
import java.util.Base64;


public class AesBridgeCLI {
    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Usage:");
            System.out.println("  java -jar AesBridgeCLI.jar <encrypt|decrypt> --mode <cbc|gcm|legacy> --data <data> --passphrase <pass> [--b64]");
            System.exit(1);
        }

        String action = args[0];
        String mode = null, data = null, passphrase = null;
        boolean b64 = false;

        for (int i = 1; i < args.length; ++i) {
            switch (args[i]) {
                case "--mode":
                    mode = args[++i];
                    break;
                case "--data":
                    data = args[++i];
                    break;
                case "--passphrase":
                    passphrase = args[++i];
                    break;
                case "--b64":
                    b64 = true;
                    break;
            }
        }

        if (mode == null || data == null || passphrase == null) {
            System.err.println("All of --mode, --data and --passphrase are required!");
            System.exit(1);
        }

        try {
            byte[] inputData;
            if (action.equals("encrypt")) {
                inputData = b64 ? Base64.getDecoder().decode(data) : data.getBytes(StandardCharsets.UTF_8);
            } else {
                inputData = data.getBytes(StandardCharsets.UTF_8);
            }

            byte[] passBytes = passphrase.getBytes(StandardCharsets.UTF_8);
            byte[] result;

            if (action.equalsIgnoreCase("encrypt")) {
                result = AesBridge.encrypt(inputData, passBytes, mode.toUpperCase());
                String out = new String(result, StandardCharsets.UTF_8);
                System.out.println(out);
            } else if (action.equalsIgnoreCase("decrypt")) {
                result = AesBridge.decrypt(inputData, passBytes, mode.toUpperCase());
                if (b64) {
                    String out = Base64.getEncoder().encodeToString(result);
                    System.out.println(out);
                } else {
                    System.out.println(new String(result, StandardCharsets.UTF_8));
                }
            } else {
                System.err.println("Unknown action: " + action);
                System.exit(1);
            }

        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            System.exit(1);
        }
    }
}
