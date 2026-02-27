package com.ida.wallet.security.common;

import org.apache.teaclave.javasdk.common.annotations.EnclaveService;

@EnclaveService
public interface AESCipherTextManagerService {
    void storeAesCipherText(byte[] cipherTextBytes);
    byte[] getAesCipherText();
}
