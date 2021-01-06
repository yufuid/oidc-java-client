package com.yufu.idaas.agent.oidc.resource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.yufu.idaas.agent.oidc.domain.OIDCConfig;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.UUID;

import static com.yufu.idaas.agent.oidc.utils.TokenUtils.genUserInfoFromToken;

/**
 * User: yunzhang
 * Date: 2019/5/15,3:53 PM
 */
@Path("/core")
public class CoreResource {
    private final OIDCConfig oidcConfig;
    private final Client client;
    private final ObjectMapper objectMapper;
    private final String STATE = UUID.randomUUID().toString();
    private final String redirect_uri = "http://127.0.0.1:7070/core/callback";

    public CoreResource(
        OIDCConfig oidcConfig,
        Client client,
        ObjectMapper objectMapper
    ) {
        this.oidcConfig = oidcConfig;
        this.client = client;
        this.objectMapper = objectMapper;
    }

    @GET
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response auth() throws Exception {
        UriBuilder uriBuilder = UriBuilder.fromUri(oidcConfig.getAuthorization_endpoint())
            .queryParam("response_type", "code")
            .queryParam("client_id", oidcConfig.getClientId())
            .queryParam("redirect_uri", redirect_uri)
            .queryParam("scope", "openid offline_access profile")
            .queryParam("state", STATE);
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
            oidcConfig.getClientId() + ":" + oidcConfig.getClientSecret()
        ).getBytes(StandardCharsets.UTF_8));

        MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", redirect_uri);

        Response
            response = client.target(oidcConfig.getToken_endpoint())
            .request()
            .header("Authorization", "Basic " + basicString)
            .post(Entity.form(form));
        return genUserInfoFromToken(client, objectMapper, oidcConfig, response);
    }

}
