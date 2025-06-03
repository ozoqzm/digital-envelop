package webcodesecurity.service;

import webcodesecurity.dto.EnvelopDto;
import webcodesecurity.util.CryptoManager;
import webcodesecurity.util.KeyManager;
import webcodesecurity.util.SignManager;
import webcodesecurity.exception.*;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

public class EnvelopService {
    private PrivateKey senderPrivateKey;
    private PublicKey senderPublicKey;
    private PublicKey receiverPublicKey;

    private final String senderPrivateKeyPath;
    private final String senderPublicKeyPath;
    private final String receiverPublicKeyPath;

    public EnvelopService(String senderPrivateKeyPath, String senderPublicKeyPath, String receiverPublicKeyPath) {
        this.senderPrivateKeyPath = senderPrivateKeyPath;
        this.senderPublicKeyPath = senderPublicKeyPath;
        this.receiverPublicKeyPath = receiverPublicKeyPath;
    }

    // 키 초기화 (메모리에 남아있는 키 리셋)
    public void resetKeys() {
        senderPrivateKey = null;
        senderPublicKey = null;
        receiverPublicKey = null;
    }

    // 공개키 개인키 생성
    public void generateAndSaveKeyPair(String privateKeyPath, String publicKeyPath) throws KeyNotFoundException {
        resetKeys(); // 생성 전 리셋
        boolean success = KeyManager.generateAndSaveKeyPair(privateKeyPath, publicKeyPath);
        if (!success) {
            throw new KeyNotFoundException("키 쌍 생성 및 저장 실패");
        }
    }

    // 전자봉투 생성
    public EnvelopDto createEnvelop(String plainText) throws EncryptionException, KeyNotFoundException, VerificationException {
        try {
            boolean loaded = loadKeysIfNecessary();
            if (!loaded) {
                throw new KeyNotFoundException("키 로딩 실패");
            }
            byte[] dataBytes = plainText.getBytes();
            byte[] signature = SignManager.signData(dataBytes, senderPrivateKey);
            byte[] publicKeyBytes = senderPublicKey.getEncoded();
            byte[] combined = concatByteArrays(dataBytes, signature, publicKeyBytes);
            SecretKey aesKey = CryptoManager.generateAESKey();
            byte[] encryptedData = CryptoManager.encryptAES(combined, aesKey);
            byte[] encryptedAesKey = CryptoManager.encryptRSA(aesKey.getEncoded(), receiverPublicKey);

            return new EnvelopDto(encryptedData, encryptedAesKey, signature.length, publicKeyBytes.length);
        } catch (VerificationException | KeyNotFoundException | EncryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionException("전자봉투 생성 중 오류 발생", e);
        }
    }

    // 위조된 전자봉투 생성
    public EnvelopDto createFakeEnvelop(String plainText) throws EncryptionException, KeyNotFoundException, VerificationException {
        try {
            boolean loaded = loadKeysIfNecessary();
            if (!loaded) {
                throw new KeyNotFoundException("키 로딩 실패");
            }
            byte[] originalBytes = plainText.getBytes();
            byte[] signature = SignManager.signData(originalBytes, senderPrivateKey);
            byte[] publicKeyBytes = senderPublicKey.getEncoded(); // 바이트 배열로 인코딩
            byte[] fakeBytes = "위조된 유언장입니다.".getBytes();
            byte[] combined = concatByteArrays(fakeBytes, signature, publicKeyBytes); // 위조된원문+전자서명+공개키 합치기
            SecretKey aesKey = CryptoManager.generateAESKey();
            byte[] encryptedData = CryptoManager.encryptAES(combined, aesKey);
            byte[] encryptedAesKey = CryptoManager.encryptRSA(aesKey.getEncoded(), receiverPublicKey);

            return new EnvelopDto(encryptedData, encryptedAesKey, signature.length, publicKeyBytes.length);
        } catch (VerificationException | KeyNotFoundException | EncryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionException("위조 전자봉투 생성 중 오류 발생", e);
        }
    }

    // 키 가져오기
    private boolean loadKeysIfNecessary() {
        try {
            if (senderPrivateKey == null) senderPrivateKey = KeyManager.loadPrivateKey(senderPrivateKeyPath);
            if (senderPublicKey == null) senderPublicKey = KeyManager.loadPublicKey(senderPublicKeyPath);
            if (receiverPublicKey == null) receiverPublicKey = KeyManager.loadPublicKey(receiverPublicKeyPath);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // 바이트 배열들 합치기
    private byte[] concatByteArrays(byte[] a, byte[] b, byte[] c) {
        if (a == null || b == null || c == null) {
            return new byte[0];
        }
        byte[] result = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        System.arraycopy(c, 0, result, a.length + b.length, c.length);
        return result;
    }

}
