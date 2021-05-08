package com.yufu.idaas.agent.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yufu.idaas.agent.oidc.domain.OIDCConfig;
import com.yufu.idaas.agent.oidc.resource.CenterResource;
import com.yufu.idaas.agent.oidc.resource.CoreResource;
import com.yufu.idaas.agent.oidc.resource.PKCEResource;
import com.yufu.idaas.agent.oidc.resource.PwdResource;
import com.yufu.idaas.agent.oidc.utils.JWKUtils;
import io.dropwizard.Application;
import io.dropwizard.setup.Environment;
import lombok.extern.slf4j.Slf4j;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.UriBuilder;

/**
 * Created by yunzhang on 6/29/16.
 */
@Slf4j
public class OIDCApplication extends Application<ClientConfiguration> {
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
        ClientConfiguration configuration,
        Environment environment
    ) throws Exception {
        OIDCConfig
            oidcConfig =
            JWKUtils.genConfig(
                configuration.getClientId(),
                configuration.getClientSecret(),
                UriBuilder.fromUri(configuration.getWellKnownUrl())
                    .build()
                    .toURL()
            );
        Client client = ClientBuilder.newClient();
        ObjectMapper objectMapper = new ObjectMapper();

        environment.jersey().register(new PKCEResource(oidcConfig, configuration.getBaseUrl(), client, objectMapper));
        environment.jersey().register(new PwdResource(oidcConfig, client, objectMapper));
        environment.jersey().register(new CoreResource(oidcConfig, configuration.getBaseUrl(), client, objectMapper));
        environment.jersey().register(new CenterResource(objectMapper, configuration.getType()));
    }

}