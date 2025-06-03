package webcodesecurity.util;

import webcodesecurity.exception.DecryptionException;
import webcodesecurity.exception.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CryptoManager {

    public static SecretKey generateAESKey() throws EncryptionException {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new EncryptionException("AES 키 생성 실패", e);
        }
    }

    public static byte[] encryptAES(byte[] data, SecretKey key) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new EncryptionException("AES 암호화 실패", e);
        }
    }

    public static byte[] decryptAES(byte[] encryptedData, byte[] keyBytes) throws DecryptionException {
        try {
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new DecryptionException("AES 복호화 실패", e);
        }
    }

    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new EncryptionException("RSA 암호화 실패", e);
        }
    }

    public static byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws DecryptionException {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new DecryptionException("RSA 복호화 실패", e);
        }
    }
}
