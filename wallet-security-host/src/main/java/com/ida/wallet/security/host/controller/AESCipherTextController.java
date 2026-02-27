package com.ida.wallet.security.host.controller;

import com.ida.wallet.security.host.enums.ErrorCodeEnum;
import com.ida.wallet.security.host.request.CiphertextRequest;
import com.ida.wallet.security.host.response.CiphertextResponse;
import com.ida.wallet.security.host.response.ResponseResult;
import com.ida.wallet.security.host.service.IAESCipherTextService;
import org.apache.teaclave.javasdk.host.AttestationReport;
import org.apache.teaclave.javasdk.host.RemoteAttestation;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.Base64;

@RestController
@RequestMapping("/security/aes")
public class AESCipherTextController {

    private final IAESCipherTextService aesService;

    public AESCipherTextController(IAESCipherTextService aesService) {
        this.aesService = aesService;
    }

    /**
     * 获取 AES 密文
     * <p>
     * 注意：
     * - Controller 永远不要暴露 byte[]
     * - 使用 Base64 作为 HTTP 安全编码
     */
    @GetMapping("/ciphertext")
    public ResponseResult<CiphertextResponse> getAesCipherText(@Valid @RequestBody CiphertextRequest request) throws Exception {

        AttestationReport attestationReport = AttestationReport.fromByteArray(request.getQuote());

        int result = RemoteAttestation.verifyAttestationReport(attestationReport);
        if (result != 0) {
            return ResponseResult.fail(ErrorCodeEnum.REMOTE_ATTESTATION_VERIFY_FAILED.getMsg(), ErrorCodeEnum.REMOTE_ATTESTATION_VERIFY_FAILED.getCode());
        }

        byte[] cipher = aesService.getAesCipherText();

        try {
            // HTTP 安全返回
            return ResponseResult.success(CiphertextResponse.of(Base64.getEncoder().encodeToString(cipher)));
        } finally {
            // host copy 及时擦除
            if (cipher != null) {
                java.util.Arrays.fill(cipher, (byte) 0);
            }
        }
    }

}
