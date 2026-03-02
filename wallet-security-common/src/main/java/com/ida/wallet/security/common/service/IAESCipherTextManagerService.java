package com.ida.wallet.security.common.service;

import org.apache.teaclave.javasdk.common.annotations.EnclaveService;

@EnclaveService
public interface IAESCipherTextManagerService {
    void storeAesCipherText(byte[] cipherTextBytes);
    byte[] getAesCipherText();
}
