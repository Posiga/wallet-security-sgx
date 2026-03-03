package com.ida.wallet.security.host;

import com.alibaba.fastjson.parser.ParserConfig;
import com.ida.wallet.security.host.config.WalletPwdConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@Slf4j
@SpringBootApplication
public class WalletSecuritySgxHostApplication {

    public static void main(String[] args) {
        DefaultApplicationArguments appArg = new DefaultApplicationArguments(args);
        // 读取钱包密码
        WalletPwdConfig.readPasswd(appArg);
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