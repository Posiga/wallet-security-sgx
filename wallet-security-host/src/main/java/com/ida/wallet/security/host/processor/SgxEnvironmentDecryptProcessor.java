package com.ida.wallet.security.host.processor;

import com.ida.wallet.security.host.config.WalletPwdConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.origin.OriginTrackedValue;
import org.springframework.core.Ordered;
import org.springframework.core.env.*;

import java.util.HashMap;
import java.util.Map;

public class SgxEnvironmentDecryptProcessor implements EnvironmentPostProcessor, Ordered {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {

        MutablePropertySources propertySources = environment.getPropertySources();

        Map<String, Object> decrypted = new HashMap<>();

        for (PropertySource<?> source : propertySources) {

            // 只扫描 application.yml
            if (!source.getName().contains("application.yml")) {
                continue;
            }

            Object rawSource = source.getSource();

            if (!(rawSource instanceof Map)) {
                continue;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> original = (Map<String, Object>) rawSource;

            for (Map.Entry<String, Object> entry : original.entrySet()) {

                Object value = entry.getValue();
                String str = null;

                if (value instanceof OriginTrackedValue) {
                    Object real = ((OriginTrackedValue) value).getValue();
                    if (real instanceof String) {
                        str = (String) real;
                    }
                } else if (value instanceof String) {
                    str = (String) value;
                }

                if (str != null && str.startsWith("enc@")) {

                    String decryptedValue = WalletPwdConfig.decryptContent(str.substring(4));
                    System.out.println("解密属性: " + entry.getKey() + ", 原值: " + str + ", 解密后: " + decryptedValue);
                    decrypted.put(entry.getKey(), decryptedValue);
                }
            }
        }

        // 关键：新增一个高优先级 PropertySource
        if (!decrypted.isEmpty()) {

            propertySources.addFirst(new MapPropertySource("sgx-decrypted", decrypted));

            System.out.println("SGX 解密 PropertySource 注入完成");
        }
    }

    @Override
    public int getOrder() {
        // 在 ConfigData 之后执行
        return Ordered.LOWEST_PRECEDENCE;
    }
}