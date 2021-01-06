package com.yufu.idaas.agent.oidc.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * User: yunzhang
 * Date: 2021/1/6
 */
public class EncodeUtils {

    public static String urlEncodeSHA256(final String strText) {
        return urlEncodeSHA(strText, "SHA-256");
    }

    private static String urlEncodeSHA(final String strText, final String strType) {
        String strResult = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(strType);
            messageDigest.update(strText.getBytes(StandardCharsets.UTF_8));
            byte[] byteBuffer = messageDigest.digest();
            strResult = Base64.getUrlEncoder().withoutPadding().encodeToString(byteBuffer);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strResult;
    }
}
