package webcodesecurity.util;

import java.io.*;
import java.security.*;

public class KeyManager {

    public static boolean generateAndSaveKeyPair(String privateKeyPath, String publicKeyPath) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            try (FileOutputStream fos = new FileOutputStream(privateKeyPath);
                 ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(privateKey); // 개인키 객체 직렬화해 파일에 저장
            }
            try (FileOutputStream fos = new FileOutputStream(publicKeyPath);
                 ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(publicKey); // 공개키 객체 직렬화해 파일에 저장
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static PrivateKey loadPrivateKey(String fileName) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName))) {
            return (PrivateKey) ois.readObject();
        } catch (Exception e) {
            throw new Exception("PrivateKey 가져오기 실패", e);
        }
    }

    public static PublicKey loadPublicKey(String fileName) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName))) {
            return (PublicKey) ois.readObject();
        } catch (Exception e) {
            throw new Exception("PublicKey 가져오기 실패", e);
        }
    }

}
