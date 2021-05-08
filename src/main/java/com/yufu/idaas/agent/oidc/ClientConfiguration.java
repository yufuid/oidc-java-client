package com.yufu.idaas.agent.oidc;

import com.yufu.idaas.agent.oidc.domain.AuthType;
import io.dropwizard.Configuration;
import lombok.Getter;

@Getter
public class ClientConfiguration extends Configuration {
    private AuthType type;
    private String clientId;
    private String clientSecret;

    private String wellKnownUrl;

    private String baseUrl;
}
