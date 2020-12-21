package com.yufu.idaas.agent.oidc.resource;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Path("/oidc")
public class CallbackResource {

    private String clientId;
    private String clientSecret;
    private String redirectUrl;
    private String tokenUrl;
    private String userInfoUrl;
    private final Client client = ClientBuilder.newClient();

    public CallbackResource(
        final String clientId,
        final String clientSecret,
        final String redirectUrl,
        final String tokenUrl,
        final String userInfoUrl
    ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUrl = redirectUrl;
        this.tokenUrl = tokenUrl;
        this.userInfoUrl = userInfoUrl;
    }

    @GET
    @Path("/callback")
    public Response getCode(
        @QueryParam("code") String code,
        @Context HttpServletRequest request
    ) {
        String basicString = Base64.getEncoder().encodeToString((
            clientId + ":" + clientSecret
        ).getBytes(StandardCharsets.UTF_8));

        MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", redirectUrl);

        Map<String, Object> tokenResponse = client.target(tokenUrl)
            .request()
            .header("Authorization", "Basic " + basicString)
            .post(Entity.form(form)).readEntity(new GenericType<Map<String, Object>>() {
            });

        String idToken = String.valueOf(tokenResponse.get("id_token"));
        String accessToken = String.valueOf(tokenResponse.get("access_token"));

        Map<String, Object> userInfo = client.target(userInfoUrl)
            .request(MediaType.APPLICATION_JSON_TYPE)
            .header("Authorization", "Bearer " + accessToken)
            .get().readEntity(new GenericType<Map<String, Object>>() {
                              }
            );
        return null;
    }
}
