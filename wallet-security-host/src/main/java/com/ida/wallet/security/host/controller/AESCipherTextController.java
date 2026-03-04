package com.ida.wallet.security.host.controller;

import com.alibaba.fastjson.JSON;
import com.ida.wallet.security.host.config.WalletPwdConfig;
import com.ida.wallet.security.host.enums.ResponseCodeEnum;
import com.ida.wallet.security.host.request.CiphertextRequest;
import com.ida.wallet.security.host.response.CiphertextResponse;
import com.ida.wallet.security.host.response.ResponseResult;
import com.ida.wallet.security.host.service.IAESCipherTextService;
import com.ida.wallet.security.host.utils.SignatureVerifyUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.teaclave.javasdk.host.AttestationReport;
import org.apache.teaclave.javasdk.host.RemoteAttestation;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Base64;

import static com.ida.wallet.security.host.enums.ResponseCodeEnum.SIGNATURE_VERIFY_FAIL;

@Slf4j
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
                                                   @RequestBody String reportStr) throws Exception {

        String method = "POST";
        String path = "/v1/aes/ciphertext";

        if (!SignatureVerifyUtil.SignatureVerify(method, path, nonce, reportStr, signature)) {
            return ResponseResult.fail(SIGNATURE_VERIFY_FAIL.getMsg(), SIGNATURE_VERIFY_FAIL.getCode());
        }

        CiphertextRequest ciphertextRequest = JSON.parseObject(WalletPwdConfig.decryptContent(reportStr), CiphertextRequest.class);

        AttestationReport attestationReport = AttestationReport.fromByteArray(ciphertextRequest.getReportBytes());

        log.info("远程证明报告解析成功，开始验证远程证明报告...");
        int result = RemoteAttestation.verifyAttestationReport(attestationReport);
        if (result != 0) {
            return ResponseResult.fail(ResponseCodeEnum.REMOTE_ATTESTATION_VERIFY_FAILED.getMsg(), ResponseCodeEnum.REMOTE_ATTESTATION_VERIFY_FAILED.getCode());
        }

        log.info("远程证明报告验证成功，开始获取 AES 密文...");
        byte[] cipher = aesService.getAesCipherText();
        log.info("获取 AES 密文成功，准备返回响应...");

        try {
            CiphertextResponse response = CiphertextResponse.builder().ciphertext(Base64.getEncoder().encodeToString(cipher)).build();
            log.info("AES 密文响应准备成功，返回响应...");
            return ResponseResult.success(WalletPwdConfig.encryptContent(JSON.toJSONString(response)));
        } finally {
            // host copy 及时擦除
            if (cipher != null) {
                Arrays.fill(cipher, (byte) 0);
            }
        }
    }

}
