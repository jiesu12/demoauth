package com.example.demoauth

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import net.minidev.json.JSONObject
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.jwt.JwtHelper
import org.springframework.security.jwt.crypto.sign.RsaSigner
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.util.JsonParser
import org.springframework.security.oauth2.common.util.JsonParserFactory
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseBody
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey


@SpringBootApplication
class DemoauthApplication {
    @Bean
    fun keyPair(): KeyPair = KeyPairGenerator.getInstance("RSA").genKeyPair()

    @Bean
    fun jsonParser(): JsonParser = JsonParserFactory.create()

    @Bean
    fun jwkSet(): JWKSet = JWKSet(RSAKey.Builder(keyPair().public as RSAPublicKey)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .keyID("key-id").build())

    @Bean
    fun signer(keyPair: KeyPair): RsaSigner = RsaSigner(keyPair.private as RSAPrivateKey)

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }
}

fun main(args: Array<String>) {
    runApplication<DemoauthApplication>(*args)
}

@Configuration
@EnableAuthorizationServer
class AuthServerConfig(val passwordEncoder: PasswordEncoder,
                       val authenticationConfiguration: AuthenticationConfiguration,
                       val customJwtAccessTokenConverter: CustomJwtAccessTokenConverter
) : AuthorizationServerConfigurerAdapter() {

    override fun configure(clients: ClientDetailsServiceConfigurer) {
        clients.inMemory()
                .withClient("client")
                .secret(passwordEncoder.encode("secret"))
                .redirectUris("http://localhost:8081")
                .authorizedGrantTypes("authorization_code", "client_credentials")
                .scopes("read")
                .autoApprove(true)
    }

    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer) {
        endpoints
                .authenticationManager(authenticationConfiguration.authenticationManager)
                .accessTokenConverter(customJwtAccessTokenConverter)
                .tokenStore(tokenStore())
    }

    @Bean
    fun tokenStore(): TokenStore = JwtTokenStore(customJwtAccessTokenConverter)
}

@Component
class CustomJwtAccessTokenConverter(val rasSigner: RsaSigner, val jsonParser: JsonParser, keyPair: KeyPair)
    : JwtAccessTokenConverter() {
    init {
        super.setKeyPair(keyPair)
    }

    override fun encode(accessToken: OAuth2AccessToken, authentication: OAuth2Authentication): String =
            JwtHelper.encode(
                    jsonParser.formatMap(accessTokenConverter.convertAccessToken(accessToken, authentication)),
                    rasSigner,
                    mapOf("kid" to "key-id")
            ).encoded
}

@EnableWebSecurity
@Configuration
class SecurityConfig : WebSecurityConfigurerAdapter() {
    @Bean
    override fun userDetailsService(): UserDetailsService {
        return InMemoryUserDetailsManager(
                User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("pass")
                        .roles("USER")
                        .build())
    }
}

@FrameworkEndpoint
internal class JwkSetEndpoint(var jwkSet: JWKSet) {
    @GetMapping("/.well-known/jwks.json")
    @ResponseBody
    fun getKey(): JSONObject = jwkSet.toJSONObject()
}
