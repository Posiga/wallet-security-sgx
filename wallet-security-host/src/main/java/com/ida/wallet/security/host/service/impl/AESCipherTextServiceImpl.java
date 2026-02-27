package com.ida.wallet.security.host.service.impl;

import com.ida.wallet.security.common.AESCipherTextManagerService;
import com.ida.wallet.security.host.enclave.EnclaveService;
import com.ida.wallet.security.host.service.IAESCipherTextService;
import org.apache.teaclave.javasdk.host.Enclave;
import org.apache.teaclave.javasdk.host.exception.ServicesLoadingException;
import org.springframework.stereotype.Service;

import java.util.Iterator;

@Service
public class AESCipherTextServiceImpl implements IAESCipherTextService {

    private final EnclaveService enclaveService;

    public AESCipherTextServiceImpl(EnclaveService enclaveService) {
        this.enclaveService = enclaveService;
    }


    @Override
    public byte[] getAesCipherText() throws ServicesLoadingException {
        Enclave enclave = enclaveService.getEnclave();
        Iterator<AESCipherTextManagerService> services = enclave.load(AESCipherTextManagerService.class);

        return services.next().getAesCipherText();
    }
}
