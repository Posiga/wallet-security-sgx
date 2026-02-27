package com.ida.wallet.security.enclave;

import com.google.auto.service.AutoService;
import com.ida.wallet.security.common.AESCipherTextManagerService;

@AutoService(AESCipherTextManagerService.class)
public class AESCipherTextManagerServiceImpl implements AESCipherTextManagerService {
    /**
     * 常驻 enclave EPC 内存
     */
    private byte[] aesCipherText;

    /**
     * 是否已经初始化
     */
    private boolean initialized = false;

    @Override
    public synchronized void storeAesCipherText(byte[] cipherTextBytes) {

        if (cipherTextBytes == null || cipherTextBytes.length == 0) {
            throw new IllegalArgumentException("cipherTextBytes is empty");
        }

        // 防止密钥被重新注入（非常重要）
        if (initialized) {
            throw new IllegalStateException("AES ciphertext already initialized");
        }

        /*
         * 必须复制：
         * Host 传入的 buffer 不可信
         * 避免外部持有引用修改 enclave 内数据
         */
        aesCipherText = new byte[cipherTextBytes.length];
        System.arraycopy(
                cipherTextBytes,
                0,
                aesCipherText,
                0,
                cipherTextBytes.length);

        initialized = true;
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
