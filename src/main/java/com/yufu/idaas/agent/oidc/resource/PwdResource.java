package com.yufu.idaas.agent.oidc.resource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.yufu.idaas.agent.oidc.domain.OIDCConfig;
import com.yufu.idaas.agent.oidc.utils.TokenUtils;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.*;
import java.text.ParseException;

@Path("/pwd")
public class PwdResource {
    private final OIDCConfig oidcConfig;
    private final Client client;
    private final ObjectMapper objectMapper;

    public PwdResource(
        OIDCConfig oidcConfig,
        Client client,
        ObjectMapper objectMapper
    ) {
        this.oidcConfig = oidcConfig;
        this.client = client;
        this.objectMapper = objectMapper;
    }

    @GET
    public Response getUserInfo(
        @QueryParam("username") String username,
        @QueryParam("password") String password,
        @Context HttpServletRequest request,
        @Context UriInfo uriInfo
    ) throws JsonProcessingException, ParseException, JOSEException {
        MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", password);
        form.add("client_id", oidcConfig.getClientId());
        form.add("client_secret", oidcConfig.getClientSecret());
        Response
            response = client.target(oidcConfig.getToken_endpoint())
            .request()
            .post(Entity.form(form));
        return TokenUtils.genUserInfoFromToken(client, objectMapper, oidcConfig, response);
    }
}
