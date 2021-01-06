package com.yufu.idaas.agent.oidc.resource;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yufu.idaas.agent.oidc.domain.AuthType;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

/**
 * User: yunzhang
 * Date: 2021/1/6
 */
@Path("/")
public class CenterResource {
    private final ObjectMapper objectMapper;
    private final AuthType authType;

    public CenterResource(
        final ObjectMapper objectMapper,
        final AuthType authType
    ) {
        this.objectMapper = objectMapper;
        this.authType = authType;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response center(@Context HttpServletRequest request, @CookieParam("data") Cookie data) {
        return Response.seeOther(UriBuilder.fromPath(data != null ? "/dashboard" : "/login").build()).build();
    }

    @GET
    @Path("/login")
    @Produces(MediaType.APPLICATION_JSON)
    public Response login(@Context HttpServletRequest request, @CookieParam("data") Cookie data) {
        String loginUri = "";
        switch (this.authType) {
            case core:
                loginUri = "/core";
                break;
            case pkce:
                loginUri = "/spa";
                break;
            case password:
                loginUri = "/pwd";
                break;
            default:
                break;
        }
        return Response.seeOther(UriBuilder.fromPath(data != null ? "/dashboard" : loginUri).build()).build();
    }

    @GET
    @Path("dashboard")
    @Produces(MediaType.APPLICATION_JSON)
    public Response dashboard(
        @Context HttpServletRequest request,
        @CookieParam("data") javax.ws.rs.core.Cookie data
    ) throws IOException {
        if (data == null) {
            return Response.ok().entity("no permission,not login in !").build();
        }
        Map<String, Object> userInfo = objectMapper.readValue(Base64.getDecoder()
            .decode(data.getValue()), new TypeReference<Map<String, Object>>() {});
        return Response.ok().entity(userInfo).build();
    }

    @GET
    @Path("/logout")
    @Produces(MediaType.APPLICATION_JSON)
    public Response logout(@Context HttpServletRequest request, @CookieParam("data") javax.ws.rs.core.Cookie data) {
        Response.ResponseBuilder responseBuilder = Response.ok().entity("you are logged out now.");
        if (data != null) {
            responseBuilder.cookie(new NewCookie("data", "", data.getPath(), data.getDomain(), null, 0, false));
        }
        return responseBuilder.build();
    }

}
