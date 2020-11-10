package com.ghrix.signer;

import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;
import java.util.TreeMap;

import static javax.xml.crypto.dsig.keyinfo.KeyValue.RSA_TYPE;

@SpringBootApplication
public class SignerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SignerApplication.class, args);
    }

}

@RestController
class Controller {

    private static final String CHARSET = "UTF-8";
    private static final String RSA_TYPE = "RSA";
    private static final String SIGN_ALGORITHM = "SHA256WithRSA";
    private static final String PRIVATE_KEY = ""; // your private key


    @PostMapping(value = "/generate", consumes = "application/json", produces = "application/json" )
    public Map<String,String> generateAuth(@RequestBody  final Map<String, String> params) throws Exception {
        System.out.println("Generating Auth for params: " + params);

        params.putIfAbsent("access_token", "${access_token}");
        params.putIfAbsent("client_id", "${client_id}");
        params.putIfAbsent("method", "${method}");
        params.putIfAbsent("format", "");
        params.putIfAbsent("biz_content", "{}");
        params.putIfAbsent("charset", "");
        params.putIfAbsent("version", "1.0");
        params.putIfAbsent("timestamp", "1970-01-01 00:00:00");
        params.putIfAbsent("sign_type", "RSA2");

        return Map.of("signature", buildSignature(params,
                params.getOrDefault("private_key", PRIVATE_KEY)));
    }


    /**
     * generate signature
     */
    private static String buildSignature(Map<String, String> params, String privateKeyStr) throws Exception {
        String signContent = buildSignContent(params);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_TYPE);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyStr.getBytes()));
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Signature signature = Signature.getInstance(SIGN_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(signContent.getBytes());
        byte[] sign = signature.sign();
        return new String(Base64.encodeBase64(sign));
    }
    /**
     * generate content to sign
     */
    private static String buildSignContent(Map<String, String> params) throws Exception {
        if (CollectionUtils.isEmpty(params)) {
            return null;
        }

        // sort by key
        TreeMap<String, String> sortedParams = new TreeMap<>();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            String key = StringUtils.trim(entry.getKey());
            String value = StringUtils.trim(entry.getValue());
            if (StringUtils.equals(key, "sign")) {
                continue;
            }
            if (StringUtils.isBlank(value)) {
                continue;
            }
            sortedParams.put(key, value);
        }
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : sortedParams.entrySet()) {
            builder.append(String.format("%s=%s&", entry.getKey(), entry.getValue()));
        }
        builder.setLength(builder.length() - 1);
        return builder.toString();
    }
    /**
     * do url encode
     */
    private static Map<String, String> urlEncode(Map<String, String> params) throws Exception {
        Map<String, String> encodedParams = Maps.newHashMap();
        if (CollectionUtils.isEmpty(params)) {
            return encodedParams;
        }
        for (Map.Entry<String, String> entry : params.entrySet()) {
            String encodedKey = URLEncoder.encode(entry.getKey(), CHARSET);
            String encodedValue = URLEncoder.encode(entry.getValue(), CHARSET);
            encodedParams.put(encodedKey, encodedValue);
        }
        return encodedParams;
    }

}
