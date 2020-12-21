package com.yufu.idaas.agent.oidc.configuration;

import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.security.interfaces.RSAPublicKey;

/**
 * User: yunzhang
 * Date: 2020/3/4
 */
@Slf4j
@Data
@Builder
public class OIDCConfiguration {
    private String issuer;
    private String authorization_endpoint;
    private String token_endpoint;
    private String jwks_uri;
    private String userinfo_endpoint;

    private RSAPublicKey publicKey;
}
