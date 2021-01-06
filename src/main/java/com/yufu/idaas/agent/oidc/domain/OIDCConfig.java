package com.yufu.idaas.agent.oidc.domain;

import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 * User: yunzhang
 * Date: 2020/3/4
 */
@Slf4j
@Data
@Builder
public class OIDCConfig {
    private String issuer;
    private String authorization_endpoint;
    private String token_endpoint;
    private String userinfo_endpoint;

    private Map<String, RSAPublicKey> publicKeys;

    private String clientId;
    private String clientSecret;
}
