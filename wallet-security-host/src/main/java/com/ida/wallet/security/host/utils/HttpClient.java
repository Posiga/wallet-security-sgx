package com.ida.wallet.security.host.utils;

import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import okhttp3.*;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class HttpClient {

    public static final MediaType JSON_TYPE = MediaType.get("application/json");

    private String credential;

    private String userAgent;

    private final OkHttpClient client;

    public HttpClient() {
        this(null, null, 20);
    }

    public HttpClient(long timeout) {
        this(null, null, timeout);
    }

    public HttpClient(String user, String password) {
        this(user, password, 20);
    }

    public HttpClient(String user, String password, long timeout) {
        if(StrUtil.isNotBlank(password)) {
            this.credential = Credentials.basic(Optional.ofNullable(user).orElse(""), password);
        }
        TrustAllCerts trustManager = new TrustAllCerts();
        this.client = new OkHttpClient.Builder()
                .sslSocketFactory(createSSLSocketFactory(trustManager), trustManager)
                .hostnameVerifier(new TrustAllHostnameVerifier())
                .connectTimeout(timeout, TimeUnit.SECONDS)
                .readTimeout(timeout, TimeUnit.SECONDS)
                .writeTimeout(timeout, TimeUnit.SECONDS)
                .build();
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public FormReq form(String url) {
        return new FormReq(url);
    }

    public GetReq get(String url) {
        return new GetReq(url);
    }

    public JsonReq json(String url) {
        return new JsonReq(url);
    }

    public OkHttpClient rawClient() {
        return client;
    }

    @SuppressWarnings("unchecked")
    public abstract class HttpReq<T extends HttpReq> {

        protected String url;
        protected String method;
        protected Request.Builder builder = new Request.Builder();

        private HttpReq(String url, String method) {
            this.url = url;
            this.method = method;
            builder.url(url);
        }

        public T header(String name, String value) {
            builder.header(name, value);
            return (T) this;
        }

        protected abstract RequestBody createBody();

        public final HttpResult execute() {
            if(credential != null) {
                builder.header("Authorization", credential);
            }
            if(userAgent != null) {
                builder.removeHeader("User-Agent").addHeader("User-Agent", userAgent);
            }
            try {
                try (Response response =  client.newCall(builder.method(method, createBody()).build()).execute()) {
                    return new HttpResult(response.code(), response.message(), response.body());
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public final String asString() {
            return execute().asString();
        }

        public final JSONObject asJson() {
            return execute().asJson();
        }

        public final JSONArray asJsonArray() {
            return execute().asJsonArray();
        }

    }

    public class GetReq extends HttpReq<GetReq> {

        private GetReq(String url) {
            super(url, "GET");
        }

        @Override
        protected RequestBody createBody() {
            return null;
        }
    }

    public class FormReq extends HttpReq<FormReq> {

        private Map<String, String> fields = new HashMap<>();

        private FormReq(String url) {
            super(url, "POST");
        }

        public FormReq field(String name, String value) {
            fields.put(name, value);
            return this;
        }

        @Override
        protected RequestBody createBody() {
            FormBody.Builder builder = new FormBody.Builder();
            fields.forEach(builder::add);
            return builder.build();
        }
    }

    public class JsonReq extends HttpReq<JsonReq> {

        private byte[] body;

        private JsonReq(String url) {
            super(url, "POST");
        }

        public JsonReq body(byte[] body) {
            this.body = body;
            return this;
        }

        public JsonReq body(Object obj) {
            this.body = JSON.toJSONString(obj).getBytes(StandardCharsets.UTF_8);
            return this;
        }

        @Override
        protected RequestBody createBody() {
            if(body == null) {
                throw new IllegalStateException("body must be set for json request");
            }
            return RequestBody.create(JSON_TYPE, body);
        }

    }

    public static class HttpResult {
        private int code;
        private String message;
        private String body;
        private byte[] bytes;

        private HttpResult(int code, String message, ResponseBody body) throws IOException {
            this.code = code;
            this.message = message;
            if (body != null) {
                this.body = body.string();
                this.bytes = this.body.getBytes();
            }
        }

        public int getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }

        public String getBody() {
            return body;
        }

        public byte[] getBytes() {
            return bytes;
        }

        public byte[] raw() {
            return bytes;
        }

        public String asString() {
            return body;
        }

        public JSONObject asJson() {
            return JSON.parseObject(body);
        }

        public JSONArray asJsonArray() {
            return JSON.parseArray(body);
        }

    }

    private static class TrustAllCerts implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {return new X509Certificate[0];}
    }

    private static class TrustAllHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    private static SSLSocketFactory createSSLSocketFactory(X509TrustManager trustManager) {
        SSLSocketFactory ssfFactory = null;
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null,  new TrustManager[] { trustManager }, new SecureRandom());
            ssfFactory = sc.getSocketFactory();
        } catch (Exception e) {
            //
        }
        return ssfFactory;
    }
}
