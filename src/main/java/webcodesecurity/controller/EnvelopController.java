package webcodesecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import webcodesecurity.dto.EnvelopDto;
import webcodesecurity.dto.VerificationDto;
import webcodesecurity.service.EnvelopService;
import webcodesecurity.service.VerificationService;
import webcodesecurity.util.KeyManager;
import java.security.PrivateKey;

@Controller
public class EnvelopController {

    private static final String KEY_DIR = "keys/";
    private static final String SENDER_PRIVATE_KEY_PATH = KEY_DIR + "senderPrivate.key";
    private static final String SENDER_PUBLIC_KEY_PATH = KEY_DIR + "senderPublic.key";
    private static final String RECEIVER_PRIVATE_KEY_PATH = KEY_DIR + "receiverPrivate.key";
    private static final String RECEIVER_PUBLIC_KEY_PATH = KEY_DIR + "receiverPublic.key";

    private final EnvelopService envelopService;
    private final VerificationService verificationService;

    public EnvelopController() {
        this.envelopService = new EnvelopService(
                SENDER_PRIVATE_KEY_PATH,
                SENDER_PUBLIC_KEY_PATH,
                RECEIVER_PUBLIC_KEY_PATH);
        this.verificationService = new VerificationService();
    }

    @GetMapping("/create")
    public String createForm() {
        return "create-will";
    }

    @PostMapping("/create/generateSenderKeys")
    public String generateSenderKeys(Model model) {
        try {
            envelopService.generateAndSaveKeyPair(SENDER_PRIVATE_KEY_PATH, SENDER_PUBLIC_KEY_PATH);
            model.addAttribute("message", "발신자 키가 생성되었습니다.");
        } catch (Exception e) {
            model.addAttribute("message", "발신자 키 생성 중 오류가 발생했습니다: " + e.getMessage());
        }
        return "create-will";
    }

    @PostMapping("/create/generateReceiverKeys")
    public String generateReceiverKeys(Model model) {
        try {
            envelopService.generateAndSaveKeyPair(RECEIVER_PRIVATE_KEY_PATH, RECEIVER_PUBLIC_KEY_PATH);
            model.addAttribute("message", "수신자 키가 생성되었습니다.");
        } catch (Exception e) {
            model.addAttribute("message", "수신자 키 생성 중 오류가 발생했습니다: " + e.getMessage());
        }
        return "create-will";
    }

    // 전자봉투 생성
    @PostMapping("/create")
    public String createEnvelop(@RequestParam String plainText, Model model) {
        try {
            EnvelopDto dto = envelopService.createEnvelop(plainText);
            model.addAttribute("envelop", dto);
            return "created-will";
        } catch (Exception e) {
            model.addAttribute("message", "전자봉투 생성 중 오류가 발생했습니다: " + e.getMessage());
            return "create-will";
        }
    }

    // 위조된 전자봉투 생성
    @PostMapping("/createFake")
    public String createFakeEnvelop(@RequestParam String plainText, Model model) {
        try {
            EnvelopDto dto = envelopService.createFakeEnvelop(plainText);
            model.addAttribute("envelop", dto);
            return "created-will";
        } catch (Exception e) {
            model.addAttribute("message", "위조 전자봉투 생성 중 오류가 발생했습니다: " + e.getMessage());
            return "create-will";
        }
    }

    // 전자봉투 검증 요청
    @PostMapping("/verify")
    public String verify(@ModelAttribute EnvelopDto envelop, Model model) {
        try {
            PrivateKey receiverPrivateKey = KeyManager.loadPrivateKey(RECEIVER_PRIVATE_KEY_PATH);
            VerificationDto result = verificationService.verify(envelop, receiverPrivateKey);

            model.addAttribute("envelop", envelop);
            model.addAttribute("message", result.isValid() ? "전자봉투가 유효합니다." : "전자봉투가 유효하지 않습니다.");
            model.addAttribute("plainText", result.getPlainText());
        } catch (Exception e) {
            model.addAttribute("message", "오류가 발생했습니다: " + e.getMessage());
        }
        return "verify-will";
    }
}
