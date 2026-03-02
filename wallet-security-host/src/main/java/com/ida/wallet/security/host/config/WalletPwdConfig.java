package com.ida.wallet.security.host.config;

import com.ida.wallet.security.host.utils.AesBase58;
import com.ulisesbocchio.jasyptspringboot.EncryptablePropertyResolver;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

@Configuration
public class WalletPwdConfig {

    private static String aesKeyStr = "1234567890123456";

    public static String getAesKeyStr() {
        return aesKeyStr;
    }

    public static String readPasswd(DefaultApplicationArguments args) {
        if(args.containsOption("configEncrypted") && "false".equalsIgnoreCase(args.getOptionValues("configEncrypted").get(0))) {
            return null;
        }

        String classPath = System.getProperty("java.class.path");
        if(classPath.contains("idea_rt.jar")) {
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            try {
                System.out.print("请输入密码:");
                aesKeyStr = br.readLine();
            } catch (IOException e) {}
        } else {
            Console console = System.console();
            char[] password = console.readPassword("请输入密码:");
            aesKeyStr = new String(password);
        }

        while (!Arrays.asList(16, 24, 32).contains(aesKeyStr.length())) {
            System.out.println("您输入的密码不正确，请重新输入！");
            aesKeyStr = readPasswd(args);
        }

        return aesKeyStr;
    }

    public static String decryptContent(String encryptedContent) {
        return AesBase58.decrypt(encryptedContent, aesKeyStr);
    }

    public static String encryptContent(String plainContent) {
        return AesBase58.encrypt(plainContent, aesKeyStr);
    }

    @Bean(name="encryptablePropertyResolver")
    public EncryptablePropertyResolver encryptablePropertyResolver() {
        return new EncryptionPropertyResolver();
    }

    class EncryptionPropertyResolver implements EncryptablePropertyResolver {

        private static final String enc = "enc@";

        @Override
        public String resolvePropertyValue(String value) {
            if(StringUtils.isEmpty(value) || value.length() < enc.length()) {
                return value;
            }
            String profiex = value.substring(0, enc.length());
            if(profiex.equalsIgnoreCase(enc)) {
                return decryptContent(value.substring(enc.length()));
            }
            return value;
        }
    }
}
