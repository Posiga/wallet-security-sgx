package com.ida.wallet.security.enclave;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AESCipherTextManagerServiceImplTest {

    @Test
    public void testAESCipherTextManagerServiceImpl() {
        // 创建服务
        AESCipherTextManagerServiceImpl service = new AESCipherTextManagerServiceImpl();

        // 准备测试数据
        byte[] cipherText = new byte[]{1, 2, 3, 4};

        // 存储
        service.storeAesCipherText(cipherText);

        // 获取
        byte[] result = service.getAesCipherText();

        // 校验结果一致
        Assertions.assertArrayEquals(cipherText, result);
    }

}
