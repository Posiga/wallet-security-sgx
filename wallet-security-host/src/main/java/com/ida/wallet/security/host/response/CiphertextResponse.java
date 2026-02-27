package com.ida.wallet.security.host.response;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CiphertextResponse {

    private String ciphertext; // Base64 encoded AES ciphertext

    public CiphertextResponse(String ciphertext) {

    }

    public static CiphertextResponse of(String ciphertext) {
        return new CiphertextResponse(ciphertext);
    }

}
