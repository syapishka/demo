package com.example.syasenk.demo.core;

import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;

import javax.naming.AuthenticationException;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class JWTCore {

    @Value("${testing.app.secret}")
    private String secret;

    @Value("${testing.app.lifetime}")
    private int lifetime;

    private final String TOKEN_HEADER = "Authorization";
    private final String TOKEN_PREFIX = "Bearer ";


    public String createJWTToken(Authentication authentication){
        UserDetailsImpl userDetails = (UserDetailsImpl)authentication.getPrincipal();

        return Jwts.builder()
                .setExpiration(new Date((new Date()).getTime() + lifetime))
                .setSubject((userDetails.getUsername()))
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

}
