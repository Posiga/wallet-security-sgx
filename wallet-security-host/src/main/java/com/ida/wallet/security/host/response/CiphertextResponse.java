package com.ida.wallet.security.host.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class CiphertextResponse {

    private String ciphertext; // Base64 encoded AES ciphertext

}
