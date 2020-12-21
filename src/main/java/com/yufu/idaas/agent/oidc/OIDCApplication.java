package com.yufu.idaas.agent.oidc;

import com.yufu.idaas.agent.oidc.configuration.OIDCConfiguration;
import com.yufu.idaas.agent.oidc.configuration.YufuConfiguration;
import com.yufu.idaas.agent.oidc.resource.OIDCResource;
import com.yufu.idaas.agent.oidc.utils.JWKUtils;
import io.dropwizard.Application;
import io.dropwizard.setup.Environment;
import lombok.extern.slf4j.Slf4j;

import javax.ws.rs.core.UriBuilder;

/**
 * Created by yunzhang on 6/29/16.
 */
@Slf4j
public class OIDCApplication extends Application<YufuConfiguration> {
    /**
     * The service's entry point. This service runs as a simple Java application.
     *
     * @param args the program arguments
     */
    public static void main(String[] args) throws Exception {
        new OIDCApplication().run(args);
    }

    @Override
    public void run(
        YufuConfiguration configuration,
        Environment environment
    ) throws Exception {
        OIDCConfiguration
            oidcConfiguration =
            JWKUtils.getProviderRSAJWK(UriBuilder.fromUri(configuration.getWellKnownUrl())
                .build()
                .toURL()
            );

        environment.jersey().register(new OIDCResource(configuration, oidcConfiguration));
    }

}