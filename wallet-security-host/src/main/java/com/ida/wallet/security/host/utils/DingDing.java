package com.ida.wallet.security.host.utils;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
public class DingDing {
    private static HttpClient httpClient = new HttpClient(10);
    private static String dingdingBaseUrl = "https://oapi.dingtalk.com/robot/send?access_token=";

    //钱包报错群,钱包报错Reboot
    public static String walletAccessToken = "f77e1da117c1df5edccf9deb3ac228a57334499a7dc4436b65ec4a3072081424";

    private static Cache<Integer, Boolean> msgCache =
        CacheBuilder.newBuilder().maximumSize(1000).expireAfterWrite(10, TimeUnit.MINUTES).build();

    //发送到钱包组
    public static void sendToWallet(String title, String text) {
        if (null == msgCache.getIfPresent(text.hashCode())) {
            msgCache.put(text.hashCode(), true);
            send(walletAccessToken, title, text);
        }
    }

    private static void send(String accessToken, String title, String text) {
        Map<String, Object> message = new HashMap<>();
        message.put("msgtype", "markdown");
        Map<String, Object> markdown = new HashMap<>();
        markdown.put("title", title);
        markdown.put("text", text);
        message.put("markdown", markdown);

        try {
            httpClient.json(dingdingBaseUrl + accessToken).body(message).execute();
        } catch (Throwable e) {
            log.error("发送钉钉异常, url {}, title {}, text {}", accessToken, title, text, e);
        }
    }
}
