package webcodesecurity.dto;

public class VerificationDto {
    private final boolean valid; // 검증 결과
    private final String plainText;  // 복호화된 원문

    public VerificationDto(boolean valid, String plainText) {
        this.valid = valid;
        this.plainText = plainText;
    }

    public boolean isValid() {
        return valid;
    }

    public String getPlainText() {
        return plainText;
    }
}
