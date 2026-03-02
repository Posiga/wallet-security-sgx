package com.ida.wallet.security.host.utils;

import cn.hutool.crypto.digest.DigestUtil;
import com.ida.wallet.security.host.config.WalletPwdConfig;

public class SignatureVerifyUtil {
    public static boolean SignatureVerify(String method, String path, String nonce, String requestData, String signature) {
        StringBuffer signatureDataSb = new StringBuffer(WalletPwdConfig.getAesKeyStr()).append("|")
            .append(method.toUpperCase()).append("|")
            .append(path).append("|")
            .append(nonce).append("|")
            .append(requestData);
        String calculateSignature = DigestUtil.sha256Hex(signatureDataSb.toString());
        return calculateSignature.equals(signature) ? true : false;
    }
}
