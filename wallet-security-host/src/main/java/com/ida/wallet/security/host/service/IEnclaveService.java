package com.ida.wallet.security.host.service;

import org.apache.teaclave.javasdk.host.exception.EnclaveCreatingException;
import org.apache.teaclave.javasdk.host.exception.EnclaveDestroyingException;
import org.apache.teaclave.javasdk.host.exception.ServicesLoadingException;

public interface IEnclaveService {

    void create() throws EnclaveCreatingException;

    void destroy() throws EnclaveDestroyingException;

    void injectAESCipherText(byte[] cipher) throws ServicesLoadingException;

}
