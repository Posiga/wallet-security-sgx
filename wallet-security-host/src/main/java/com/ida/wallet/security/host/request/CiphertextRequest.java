package com.ida.wallet.security.host.request;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

/**
 * 远程证明请求，用于获取 AES Ciphertext
 */
@Getter
@Setter
public class CiphertextRequest {

    @NotNull
    private byte[] quote;

    @NotBlank
    private String nonce;
}
