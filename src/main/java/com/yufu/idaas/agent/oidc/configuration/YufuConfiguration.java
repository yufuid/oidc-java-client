package com.yufu.idaas.agent.oidc.configuration;

import io.dropwizard.Configuration;
import lombok.Getter;

@Getter
public class YufuConfiguration extends Configuration {
    private String type;
    private String clientId;
    private String clientSecret;

    private String wellKnownUrl;
    private String redirectUrl;
}
