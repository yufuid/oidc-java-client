package com.yufu.idaas.agent.oidc.resource;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.yufu.idaas.agent.oidc.configuration.OIDCConfiguration;
import com.yufu.idaas.agent.oidc.configuration.YufuConfiguration;
import com.yufu.idaas.agent.oidc.utils.JWKUtils;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * User: yunzhang
 * Date: 2019/5/15,3:53 PM
 */
@Path("/")
public class OIDCResource {
    private final YufuConfiguration configuration;
    private final OIDCConfiguration oidcConfiguration;
    private final Client client = ClientBuilder.newClient();
    private ObjectMapper objectMapper = new ObjectMapper();
    private String STATE = UUID.randomUUID().toString();
    private String codeVerifier = UUID.randomUUID().toString().replace("-", "");

    public OIDCResource(YufuConfiguration configuration, OIDCConfiguration oidcConfiguration) {
        this.configuration = configuration;
        this.oidcConfiguration = oidcConfiguration;
    }

    @GET
    @Path("/")
    @Produces(MediaType.APPLICATION_JSON)
    public Response center(@Context HttpServletRequest request, @CookieParam("data") Cookie data) {
        return Response.seeOther(UriBuilder.fromPath(data != null ? "/dashboard" : "/login").build()).build();
    }

    @GET
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response auth() throws Exception {
        if ("password".equals(configuration.getType())) {
            MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
            form.add("grant_type", "password");
            form.add("redirect_uri", configuration.getRedirectUrl());
            form.add("username", "yunzhang2@yufuid.com");
            form.add("password", "Yufuid@1qaz");
            form.add("client_id", configuration.getClientId());
            form.add("client_secret", configuration.getClientSecret());
            Response
                response = client.target(oidcConfiguration.getToken_endpoint())
                .request()
                .post(Entity.form(form));
            Map<String, Object> token = response.readEntity(new GenericType<Map<String, Object>>() {});
            if (response.getStatus() != 200) {
                return Response.ok().entity(token).type(MediaType.APPLICATION_JSON_TYPE).build();
            }
            String idToken = String.valueOf(token.get("id_token"));

            SignedJWT jwt = SignedJWT.parse(idToken);
            Preconditions.checkArgument(jwt.getJWTClaimsSet().getExpirationTime().after(new Date()));
            Preconditions.checkArgument(JWKUtils.verify(jwt, oidcConfiguration.getPublicKeys()));

            String accessToken = String.valueOf(token.get("access_token"));
            Map<String, Object> userInfo = client.target(oidcConfiguration.getUserinfo_endpoint())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .header("Authorization", "Bearer " + accessToken)
                .get().readEntity(new GenericType<Map<String, Object>>() {});

            Response.ResponseBuilder responseBuilder = Response.seeOther(UriBuilder.fromPath("/dashboard").build());

            responseBuilder.cookie(new NewCookie(
                "data",
                Base64.getEncoder()
                    .encodeToString(objectMapper.writeValueAsString(userInfo).getBytes(StandardCharsets.UTF_8))
            ));
            return responseBuilder.build();
        }

        UriBuilder uriBuilder = UriBuilder.fromUri(oidcConfiguration.getAuthorization_endpoint())
            .queryParam("response_type", "code")
            .queryParam("client_id", configuration.getClientId())
            .queryParam("redirect_uri", configuration.getRedirectUrl())
            .queryParam("scope", "openid offline_access profile")
//            .queryParam("audience", "https://test.yunzhang.com")
            .queryParam("state", STATE);
        if ("pkce".equals(configuration.getType())) {
            String codeChallenge = urlEncodeSHA256(codeVerifier);
            uriBuilder.queryParam("code_challenge", codeChallenge);
        }
        return Response.seeOther(
            uriBuilder.build()
        ).build();

    }

    @GET
    @Path("/callback")
    public Response getCode(
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
            configuration.getClientId() + ":" +
                ("pkce".equals(configuration.getType()) ? codeVerifier : configuration.getClientSecret())
        ).getBytes(StandardCharsets.UTF_8));

        MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", configuration.getRedirectUrl());
//        form.add("client_id", configuration.getClientId());
//        form.add("client_secret", configuration.getClientSecret());
//        form.add("code_verifier", codeVerifier);

        Response
            response = client.target(oidcConfiguration.getToken_endpoint())
            .request()
            .header("Authorization", "Basic " + basicString)
            .post(Entity.form(form));
        Map<String, Object> token = response.readEntity(new GenericType<Map<String, Object>>() {});
        if (response.getStatus() != 200) {
            return Response.ok().entity(token).type(MediaType.APPLICATION_JSON_TYPE).build();
        }
        String idToken = String.valueOf(token.get("id_token"));

        SignedJWT jwt = SignedJWT.parse(idToken);
        Preconditions.checkArgument(jwt.getJWTClaimsSet().getExpirationTime().after(new Date()));
        Preconditions.checkNotNull(jwt.getJWTClaimsSet().getIssuer(), "empty issuer");
        Preconditions.checkNotNull(jwt.getJWTClaimsSet().getAudience(), "empty audience");

        Preconditions.checkArgument(JWKUtils.verify(jwt, oidcConfiguration.getPublicKeys()));
        Preconditions.checkArgument(jwt.getJWTClaimsSet().getSubject() != null, "empty subject");

        String accessToken = String.valueOf(token.get("access_token"));
        Map<String, Object> userInfo = client.target(oidcConfiguration.getUserinfo_endpoint())
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
                .encodeToString(objectMapper.writeValueAsString(userInfo).getBytes(StandardCharsets.UTF_8))
        ));
        return responseBuilder.build();
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
