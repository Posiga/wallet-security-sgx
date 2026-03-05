package com.ida.wallet.security.enclave.impl;

import com.google.auto.service.AutoService;
import com.ida.wallet.security.common.service.IAESCipherTextManagerService;

@AutoService(IAESCipherTextManagerService.class)
public class AESCipherTextManagerServiceImpl implements IAESCipherTextManagerService {

    private static volatile byte[] aesCipherText;

    private static volatile boolean initialized = false;

    @Override
    public synchronized void storeAesCipherText(byte[] aesCipherTextBytes) {

        if (aesCipherTextBytes == null || aesCipherTextBytes.length == 0) {
            throw new IllegalArgumentException("cipherTextBytes is empty");
        }

        // 防止密钥被重新注入
        if (initialized) {
            throw new IllegalStateException("AES ciphertext already initialized");
        }

        /*
         * 必须复制：
         * Host 传入的 buffer 不可信
         * 避免外部持有引用修改 enclave 内数据
         */
        aesCipherText = new byte[aesCipherTextBytes.length];
        System.arraycopy(
                aesCipherTextBytes,
                0,
                aesCipherText,
                0,
                aesCipherTextBytes.length);

        initialized = true;
        System.out.println("AES ciphertext stored in enclave successfully");
    }

    @Override
    public synchronized byte[] getAesCipherText() {

        if (!initialized) {
            throw new IllegalStateException("AES ciphertext not initialized");
        }

        /*
         * 永远不要返回内部数组引用
         * 否则调用方可以修改 enclave 内存
         */
        byte[] copy = new byte[aesCipherText.length];
        System.arraycopy(aesCipherText, 0, copy, 0, aesCipherText.length);

        return copy;
    }
}
