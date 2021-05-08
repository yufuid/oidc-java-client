package com.yufu.idaas.agent.oidc.resource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.yufu.idaas.agent.oidc.domain.OIDCConfig;
import com.yufu.idaas.agent.oidc.utils.TokenUtils;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.UUID;

import static com.yufu.idaas.agent.oidc.utils.EncodeUtils.urlEncodeSHA256;

/**
 * User: yunzhang
 * Date: 2019/5/15,3:53 PM
 * <p>
 * Proof Key for Code Exchange
 */

@Path("/pkce")
public class PKCEResource {
    private final OIDCConfig oidcConfig;
    private final Client client;
    private final ObjectMapper objectMapper;
    private final String STATE = UUID.randomUUID().toString();

    private final String codeVerifier = UUID.randomUUID().toString().replace("-", "");
    private final String redirect_uri;

    public PKCEResource(
        OIDCConfig oidcConfig,
        String baseUrl,
        Client client,
        ObjectMapper objectMapper
    ) {
        this.oidcConfig = oidcConfig;
        this.redirect_uri = baseUrl + "/pkce/callback";
        this.client = client;
        this.objectMapper = objectMapper;
    }

    @GET
    public Response auth() {
        String codeChallenge = urlEncodeSHA256(codeVerifier);

        UriBuilder uriBuilder = UriBuilder.fromUri(oidcConfig.getAuthorization_endpoint())
            .queryParam("response_type", "code")
            .queryParam("client_id", oidcConfig.getClientId())
            .queryParam("redirect_uri", redirect_uri)
            .queryParam("scope", "openid offline_access profile")
            .queryParam("state", STATE)
            .queryParam("code_challenge", codeChallenge);
        return Response.seeOther(
            uriBuilder.build()
        ).build();
    }

    @GET
    @Path("/callback")
    public Response callback(
        @QueryParam("code") String code,
        @QueryParam("state") String state,
        @Context HttpServletRequest request
    ) throws
        ParseException,
        JOSEException,
        IOException {
        if (StringUtils.isBlank(code)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        if (!this.STATE.equals(state)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        String basicString = Base64.getEncoder().encodeToString((
            oidcConfig.getClientId() + ":" + codeVerifier
        ).getBytes(StandardCharsets.UTF_8));

        MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", redirect_uri);
        form.add("code_verifier", codeVerifier);

        Response
            response = client.target(oidcConfig.getToken_endpoint())
            .request()
            .header("Authorization", "Basic " + basicString)
            .post(Entity.form(form));
        return TokenUtils.genUserInfoFromToken(client, objectMapper, oidcConfig, response);
    }
}
