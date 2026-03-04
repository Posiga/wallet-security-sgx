package com.ida.wallet.security.host;

import com.alibaba.fastjson.parser.ParserConfig;
import com.ida.wallet.security.host.config.WalletPwdConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.util.List;

@Slf4j
@SpringBootApplication
public class WalletSecuritySgxHostApplication {

    public static void main(String[] args) throws IOException {
        // 1.读取控制台 AES Key
        DefaultApplicationArguments appArg = new DefaultApplicationArguments(args);
        WalletPwdConfig.readPasswd(appArg);

        // 2.获取激活 profile
        String profile = System.getProperty("spring.profiles.active");
        if (profile == null || profile.isEmpty()) {
            profile = "default";
        }

        // 3.加载对应 profile 的 application.yml
        Resource resource = new ClassPathResource("application-" + profile + ".yml");
        if (!resource.exists()) {
            resource = new ClassPathResource("application.yml"); // fallback
        }

        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        List<PropertySource<?>> yamlSources = loader.load("applicationConfig: [" + resource.getFilename() + "]", resource);

        // 4.解密 SSL 密码并写入系统属性
        for (PropertySource<?> ps : yamlSources) {
            Object keyStorePwd = ps.getProperty("server.ssl.key-store-password");
            Object trustStorePwd = ps.getProperty("server.ssl.trust-store-password");

            if (keyStorePwd instanceof String) {
                String str = (String) keyStorePwd;
                if (str.startsWith("enc@")) {
                    String decrypted = WalletPwdConfig.decryptContent(str.substring(4));
                    System.setProperty("server.ssl.key-store-password", decrypted);
                    System.out.println("解密 key-store-password 成功");
                }
            }

            if (trustStorePwd instanceof String) {
                String str = (String) trustStorePwd;
                if (str.startsWith("enc@")) {
                    String decrypted = WalletPwdConfig.decryptContent(str.substring(4));
                    System.setProperty("server.ssl.trust-store-password", decrypted);
                    System.out.println("解密 trust-store-password 成功");
                }
            }
        }

        // 5.启动 Spring Boot
        SpringApplication.run(WalletSecuritySgxHostApplication.class, args);
    }

    @Bean
    public void fastJsonSecurityCheck() {
        ParserConfig.getGlobalInstance().setSafeMode(true);
        boolean safeMode = ParserConfig.getGlobalInstance().isSafeMode();
        boolean autoType = ParserConfig.getGlobalInstance().isAutoTypeSupport();
        log.info("fastjson配置, safeMode:{}, autoType:{}", safeMode, autoType);

        if(!safeMode || autoType) {
            log.error("fastjson安全配置错误，请修改检查后启动，现有配置safeMode:{}, autoType:{},应为safeMode:true, autoType:false", safeMode, autoType);
            System.exit(-1);
        }
    }
}