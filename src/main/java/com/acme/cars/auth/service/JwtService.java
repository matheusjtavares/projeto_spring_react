package com.acme.cars.auth.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class JwtService {
    private static final String JWT_SECRET = "secret";
    private static final String ISSUER = "ACME INC";
    private Algorithm algorithm(){
        return Algorithm.HMAC256(JWT_SECRET);
    }
    public String generateToken(Authentication authenticate){
        String name = authenticate.getName();
        List<String> roles = authenticate.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        Instant now = Instant.now();
        Instant expiresAt = now.plus(1,ChronoUnit.HOURS);
        String jwt = JWT.create()
            .withIssuer(ISSUER)
            .withSubject(name)
            .withIssuedAt(now)
            .withExpiresAt(expiresAt)
            .withClaim("roles",roles)
            .sign(algorithm());
        return jwt;
    }

    public String getUsernameFromToken(String token){
        return decode(token).getSubject();
    }

    public List<String> getRolesFromToken(String token){
        return decode(token).getClaim("roles").asList(String.class);
    }
    public boolean isValid(String token){
        decode(token);
        return true;
    }
    private DecodedJWT decode(String token){
        return JWT.require(algorithm())
            .withIssuer(ISSUER)
            .build()
            .verify(token);
    } 
}
