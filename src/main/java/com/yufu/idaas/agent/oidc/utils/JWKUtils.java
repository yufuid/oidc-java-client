package com.yufu.idaas.agent.oidc.utils;

import com.google.common.base.Preconditions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.yufu.idaas.agent.oidc.configuration.OIDCConfiguration;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class JWKUtils {

    public static boolean verify(SignedJWT jwt, Map<String, RSAPublicKey> publicKeys) throws JOSEException {
        String kid = jwt.getHeader().getKeyID();
        RSAPublicKey rsaPublicKey = publicKeys.get(kid);
        if (rsaPublicKey == null) {
            return false;
        }
        RSASSAVerifier verifier = new RSASSAVerifier(rsaPublicKey);
        return jwt.verify(verifier);
    }

    public static OIDCConfiguration getProviderRSAJWK(URL wellKnownUrl) throws
        IllegalArgumentException,
        IOException,
        ParseException, java.text.ParseException, JOSEException {

        OIDCConfiguration.OIDCConfigurationBuilder configurationBuilder = OIDCConfiguration.builder();

        JSONObject json = getObjectFromUrl(wellKnownUrl);
        configurationBuilder.issuer(json.get("issuer").toString());
        configurationBuilder.authorization_endpoint(json.get("authorization_endpoint").toString());
        configurationBuilder.token_endpoint(json.get("token_endpoint").toString());
        configurationBuilder.jwks_uri(json.get("jwks_uri").toString());
        configurationBuilder.userinfo_endpoint(json.get("userinfo_endpoint").toString());

        JSONObject jwtObject = getObjectFromUrl(UriBuilder.fromUri(json.get("jwks_uri").toString()).build().toURL());

        // Find the RSA signing key
        Map<String, RSAPublicKey> rsaPublicKeyMap = new HashMap<>();
        JSONArray keyList = (JSONArray) jwtObject.get("keys");
        for (Object key : keyList) {
            JSONObject k = (JSONObject) key;
            if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
                rsaPublicKeyMap.put(k.get("kid").toString(), RSAKey.parse(k).toRSAPublicKey());
            }
        }
        configurationBuilder.publicKeys(rsaPublicKeyMap);
        return configurationBuilder.build();
    }

    private static JSONObject getObjectFromUrl(URL url) throws ParseException, IOException {
        // Read all data from stream
        StringBuilder sb = new StringBuilder();
        try (Scanner scanner = new Scanner(url.openStream());) {
            while (scanner.hasNext()) {
                sb.append(scanner.next());
            }
        }

        // Parse the data as json
        String jsonString = sb.toString();

        Object o = new JSONParser(JSONParser.USE_HI_PRECISION_FLOAT |
            JSONParser.ACCEPT_TAILLING_SPACE).parse(jsonString);
        Preconditions.checkArgument(o instanceof JSONObject);

        return (JSONObject) o;
    }

}
