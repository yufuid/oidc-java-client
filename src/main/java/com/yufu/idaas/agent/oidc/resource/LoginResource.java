package com.yufu.idaas.agent.oidc.resource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.util.UUID;

@Path("/oidc")
public class LoginResource {
    private String clientId;
    private String authorizationUrl;
    private String redirectUrl;

    public LoginResource(final String clientId, final String authorizationUrl, final String redirectUrl) {
        this.clientId = clientId;
        this.authorizationUrl = authorizationUrl;
        this.redirectUrl = redirectUrl;
    }

    @GET
    @Path("/login")
    public Response login() {
        return Response.seeOther(
            UriBuilder.fromUri(authorizationUrl)
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUrl)
                .queryParam("scope", "openid")
                .queryParam("state", UUID.randomUUID().toString()).build()
        ).build();
    }
}
