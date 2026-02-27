package com.ida.wallet.security.host.service;

import org.apache.teaclave.javasdk.host.exception.ServicesLoadingException;

public interface IAESCipherTextService {
    byte[] getAesCipherText() throws ServicesLoadingException;
}
