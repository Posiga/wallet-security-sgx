package com.ida.wallet.security.host.enclave;

import com.ida.wallet.security.common.AESCipherTextManagerService;
import lombok.Getter;
import org.apache.teaclave.javasdk.host.Enclave;
import org.apache.teaclave.javasdk.host.EnclaveFactory;
import org.apache.teaclave.javasdk.host.EnclaveType;
import org.apache.teaclave.javasdk.host.exception.EnclaveCreatingException;
import org.apache.teaclave.javasdk.host.exception.EnclaveDestroyingException;
import org.apache.teaclave.javasdk.host.exception.ServicesLoadingException;
import org.springframework.stereotype.Service;

import java.util.Iterator;

@Getter
@Service
public class EnclaveService {

    private Enclave enclave;

    public void create() throws EnclaveCreatingException {
//        enclave = EnclaveFactory.create(EnclaveType.TEE_SDK);
        enclave = EnclaveFactory.create(EnclaveType.MOCK_IN_SVM);
    }

    public void injectCipher(byte[] cipher) throws ServicesLoadingException {
        Iterator<AESCipherTextManagerService> services = enclave.load(AESCipherTextManagerService.class);
        services.next().storeAesCipherText(cipher);
    }

    public void destroy() throws EnclaveDestroyingException {
        if (enclave != null) {
            enclave.destroy();
        }
    }

}
