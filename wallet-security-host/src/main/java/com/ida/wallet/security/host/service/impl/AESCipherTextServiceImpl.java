package com.ida.wallet.security.host.service.impl;

import com.ida.wallet.security.common.service.IAESCipherTextManagerService;
import com.ida.wallet.security.host.service.IAESCipherTextService;
import org.apache.teaclave.javasdk.host.Enclave;
import org.apache.teaclave.javasdk.host.exception.ServicesLoadingException;
import org.springframework.stereotype.Service;

import java.util.Iterator;

@Service
public class AESCipherTextServiceImpl implements IAESCipherTextService {

    private final EnclaveServiceImpl enclaveService;

    public AESCipherTextServiceImpl(EnclaveServiceImpl enclaveService) {
        this.enclaveService = enclaveService;
    }


    @Override
    public byte[] getAesCipherText() throws ServicesLoadingException {
        Enclave enclave = enclaveService.getEnclave();
        Iterator<IAESCipherTextManagerService> services = enclave.load(IAESCipherTextManagerService.class);

        return services.next().getAesCipherText();
    }
}
