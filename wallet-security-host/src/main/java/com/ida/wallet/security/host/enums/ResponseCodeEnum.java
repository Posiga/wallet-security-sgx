package com.ida.wallet.security.host.enums;

import lombok.Getter;

@Getter
public enum ResponseCodeEnum {
    REMOTE_ATTESTATION_VERIFY_FAILED(10001, "远程证明验证失败"),
    SUCCESS(99999, "成功");

    private final int code;
    private final String msg;

    ResponseCodeEnum(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }

}
