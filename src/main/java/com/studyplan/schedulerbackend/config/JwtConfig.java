package com.studyplan.schedulerbackend.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class JwtConfig {

    private RSAPublicKey decodePublicKey(String publicKeyStr) throws InvalidKeySpecException, NoSuchAlgorithmException {
        if (publicKeyStr == null || publicKeyStr.trim().isEmpty()) {
            throw new IllegalArgumentException("JWT public key is empty or null");
        }
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid Base64 format for JWT public key", e);
        }
    }

    private RSAPrivateKey decodePrivateKey(String privateKeyStr) throws InvalidKeySpecException, NoSuchAlgorithmException {
        if (privateKeyStr == null || privateKeyStr.trim().isEmpty()) {
            throw new IllegalArgumentException("JWT private key is empty or null");
        }
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        } catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException("Invalid Base64 format for JWT private key", e);
        }
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(
            @Value("${jwt.public-key}") String publicKeyStr,
            @Value("${jwt.private-key}") String privateKeyStr) {
        try {
            RSAPublicKey publicKey = decodePublicKey(publicKeyStr);
            RSAPrivateKey privateKey = decodePrivateKey(privateKeyStr);
            JWK jwk = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID("6e849f8e-60d6-4499-8ed8-3c041e7fb1db")
                    .build();
            JWKSet jwkSet = new JWKSet(jwk);
            return new ImmutableJWKSet<>(jwkSet);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to load RSA keys: " + e.getMessage(), e);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(@Value("${jwt.public-key}") String publicKeyStr) {
        try {
            RSAPublicKey publicKey = decodePublicKey(publicKeyStr);
            return NimbusJwtDecoder.withPublicKey(publicKey).build();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to load public key for JWT decoder: " + e.getMessage(), e);
        }
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
}