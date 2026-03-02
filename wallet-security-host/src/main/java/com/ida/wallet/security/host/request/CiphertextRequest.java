package com.ida.wallet.security.host.request;

import lombok.Getter;
import lombok.Setter;

/**
 * 远程证明请求，用于获取 AES Ciphertext
 */
@Getter
@Setter
public class CiphertextRequest {

    private byte[] reportBytes;

}
