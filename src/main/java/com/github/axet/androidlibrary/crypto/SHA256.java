package com.github.axet.androidlibrary.crypto;

import java.security.MessageDigest;

public class SHA256 {
    public static byte[] digest(byte[] buf) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(buf);
            return digest.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
