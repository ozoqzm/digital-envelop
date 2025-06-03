package webcodesecurity.dto;

import lombok.Getter;

@Getter
public class EnvelopDto {
    private final byte[] encryptedData;      // DES로 암호화된 [평문+서명+공개키]
    private final byte[] encryptedAesKey;    // RSA로 암호화된 DES 비밀키
    private final int signatureLength;       // 서명 길이
    private final int publicKeyLength;       // 공개키 길이

    public EnvelopDto(byte[] encryptedData, byte[] encryptedAesKey, int signatureLength, int publicKeyLength) {
        this.encryptedData = encryptedData;
        this.encryptedAesKey = encryptedAesKey;
        this.signatureLength = signatureLength;
        this.publicKeyLength = publicKeyLength;
    }
}
