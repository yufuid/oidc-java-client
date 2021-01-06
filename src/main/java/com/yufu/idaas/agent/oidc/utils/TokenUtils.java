package com.yufu.idaas.agent.oidc.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.yufu.idaas.agent.oidc.domain.OIDCConfig;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.*;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static javax.ws.rs.core.NewCookie.DEFAULT_MAX_AGE;

/**
 * User: yunzhang
 * Date: 2021/1/6
 */
public class TokenUtils {

    public static Response genUserInfoFromToken(
        Client client,
        ObjectMapper objectMapper,
        OIDCConfig oidcConfig,
        Response response
    ) throws
        ParseException,
        JOSEException,
        JsonProcessingException {
        Map<String, Object> token = response.readEntity(new GenericType<Map<String, Object>>() {});
        if (response.getStatus() != 200) {
            return Response.ok().entity(token).type(MediaType.APPLICATION_JSON_TYPE).build();
        }

        String idToken = String.valueOf(token.get("id_token"));

        SignedJWT jwt = SignedJWT.parse(idToken);
        Preconditions.checkArgument(jwt.getJWTClaimsSet().getExpirationTime().after(new Date()));
        Preconditions.checkNotNull(jwt.getJWTClaimsSet().getIssuer(), "empty issuer");
        Preconditions.checkNotNull(jwt.getJWTClaimsSet().getAudience(), "empty audience");

        Preconditions.checkArgument(JWKUtils.verify(jwt, oidcConfig.getPublicKeys()));
        Preconditions.checkArgument(jwt.getJWTClaimsSet().getSubject() != null, "empty subject");

        String accessToken = String.valueOf(token.get("access_token"));
        Map<String, Object> userInfo = client.target(oidcConfig.getUserinfo_endpoint())
            .request(MediaType.APPLICATION_JSON_TYPE)
            .header("Authorization", "Bearer " + accessToken)
            .get().readEntity(new GenericType<Map<String, Object>>() {});

        Response.ResponseBuilder responseBuilder = Response.seeOther(UriBuilder.fromPath("/dashboard").build());

        Preconditions.checkArgument(
            jwt.getJWTClaimsSet().getSubject().equals(userInfo.get("sub")),
            "sub in idToken not match userInfo"
        );
        responseBuilder.cookie(new NewCookie(
            "data",
            Base64.getEncoder()
                .encodeToString(objectMapper.writeValueAsString(userInfo).getBytes(StandardCharsets.UTF_8)),
            "/",
            null,
            null,
            DEFAULT_MAX_AGE,
            false
        ));
        return responseBuilder.build();
    }
}
