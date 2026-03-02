package com.ida.wallet.security.host.service.impl;

import com.ida.wallet.security.common.service.IAESCipherTextManagerService;
import com.ida.wallet.security.host.service.IEnclaveService;
import lombok.Getter;
import org.apache.teaclave.javasdk.host.Enclave;
import org.apache.teaclave.javasdk.host.EnclaveFactory;
import org.apache.teaclave.javasdk.host.EnclaveType;
import org.apache.teaclave.javasdk.host.exception.EnclaveCreatingException;
import org.apache.teaclave.javasdk.host.exception.EnclaveDestroyingException;
import org.apache.teaclave.javasdk.host.exception.ServicesLoadingException;
import org.springframework.stereotype.Service;

@Getter
@Service
public class EnclaveServiceImpl implements IEnclaveService {

    private Enclave enclave;

    @Override
    public void create() throws EnclaveCreatingException {
        enclave = EnclaveFactory.create(EnclaveType.TEE_SDK);
    }

    @Override
    public void destroy() throws EnclaveDestroyingException {
        if (enclave != null) {
            enclave.destroy();
        }
    }

    @Override
    public void injectAESCipherText(byte[] cipher) throws ServicesLoadingException {
        enclave.load(IAESCipherTextManagerService.class).next().storeAesCipherText(cipher);
    }

}
