package webcodesecurity.service;

import webcodesecurity.dto.EnvelopDto;
import webcodesecurity.dto.VerificationDto;
import webcodesecurity.util.CryptoManager;
import webcodesecurity.util.SignManager;
import webcodesecurity.exception.*;

import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class VerificationService {
    public VerificationDto verify(EnvelopDto envelop, PrivateKey receiverPrivateKey)
            throws VerificationException, DecryptionException, KeyNotFoundException {
        byte[] aesKeyBytes = null;
        byte[] combined = null;
        byte[] plainText = null;
        byte[] sign = null;
        byte[] pubKey = null;
        try {
            aesKeyBytes = CryptoManager.decryptRSA(envelop.getEncryptedAesKey(), receiverPrivateKey);
            combined = CryptoManager.decryptAES(envelop.getEncryptedData(), aesKeyBytes);
            int sigLen = envelop.getSignatureLength();
            int pubKeyLen = envelop.getPublicKeyLength();
            int plainLen = combined.length - sigLen - pubKeyLen;
            plainText = new byte[plainLen];
            sign = new byte[sigLen];
            pubKey = new byte[pubKeyLen];

            System.arraycopy(combined, 0, plainText, 0, plainLen);
            System.arraycopy(combined, plainLen, sign, 0, sigLen);
            System.arraycopy(combined, plainLen + sigLen, pubKey, 0, pubKeyLen);

            PublicKey senderPublicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pubKey));

            boolean isValid = SignManager.verifySignature(plainText, sign, senderPublicKey);
            return new VerificationDto(isValid, new String(plainText));
        } catch (DecryptionException | VerificationException | KeyNotFoundException e) {
            throw e;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyNotFoundException("발신자 공개키 복원 실패", e);
        } catch (Exception e) {
            throw new VerificationException("전자봉투 검증 중 오류 발생", e);
        } finally {
            if (aesKeyBytes != null) Arrays.fill(aesKeyBytes, (byte) 0);
            if (combined != null) Arrays.fill(combined, (byte) 0);
            if (plainText != null) Arrays.fill(plainText, (byte) 0);
            if (sign != null) Arrays.fill(sign, (byte) 0);
            if (pubKey != null) Arrays.fill(pubKey, (byte) 0);
        }
    }

}
