package com.ida.wallet.security.host.controller;

import com.alibaba.fastjson.JSON;
import com.ida.wallet.security.host.config.WalletPwdConfig;
import com.ida.wallet.security.host.enums.ResponseCodeEnum;
import com.ida.wallet.security.host.request.CiphertextRequest;
import com.ida.wallet.security.host.response.CiphertextResponse;
import com.ida.wallet.security.host.response.ResponseResult;
import com.ida.wallet.security.host.service.IAESCipherTextService;
import com.ida.wallet.security.host.utils.SignatureVerifyUtil;
import org.apache.teaclave.javasdk.host.AttestationReport;
import org.apache.teaclave.javasdk.host.RemoteAttestation;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Base64;

import static com.ida.wallet.security.host.enums.ResponseCodeEnum.SIGNATURE_VERIFY_FAIL;

@RestController
@RequestMapping("/v1/aes")
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
    @PostMapping("/ciphertext")
    public ResponseResult<String> getAesCipherText(@RequestHeader("nonce") String nonce,
                                                               @RequestHeader("signature") String signature,
                                                               @RequestBody String reportStr
                                                                ) throws Exception {

        String method = "POST";
        String path = "/v1/aes/ciphertext";

        if (!SignatureVerifyUtil.SignatureVerify(method, path, nonce, reportStr, signature)) {
            return ResponseResult.fail(SIGNATURE_VERIFY_FAIL.getMsg(), SIGNATURE_VERIFY_FAIL.getCode());
        }

        CiphertextRequest ciphertextRequest = JSON.parseObject(WalletPwdConfig.decryptContent(reportStr), CiphertextRequest.class);

        AttestationReport attestationReport = AttestationReport.fromByteArray(ciphertextRequest.getReportBytes());

        int result = RemoteAttestation.verifyAttestationReport(attestationReport);
        if (result != 0) {
            return ResponseResult.fail(ResponseCodeEnum.REMOTE_ATTESTATION_VERIFY_FAILED.getMsg(), ResponseCodeEnum.REMOTE_ATTESTATION_VERIFY_FAILED.getCode());
        }

        byte[] cipher = aesService.getAesCipherText();

        try {
            CiphertextResponse response = CiphertextResponse.builder().ciphertext(Base64.getEncoder().encodeToString(cipher)).build();
            // HTTP 安全返回
            return ResponseResult.success(WalletPwdConfig.encryptContent(JSON.toJSONString(response)));
        } finally {
            // host copy 及时擦除
            if (cipher != null) {
                Arrays.fill(cipher, (byte) 0);
            }
        }
    }

}
