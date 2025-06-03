package webcodesecurity.util;

import java.security.*;

public class SignManager {

    // 전자서명 생성
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(data);
            return signer.sign();
    }

    // 전자서명 검증
    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(signature);

    }
}
