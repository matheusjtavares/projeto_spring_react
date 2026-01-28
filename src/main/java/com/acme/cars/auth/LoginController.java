package com.acme.cars.auth;

import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import com.acme.cars.auth.dto.LoginJwtResponse;
import com.acme.cars.auth.dto.LoginRequest;
import com.acme.cars.auth.service.JwtService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/login")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
            ) 
        );

        String token = jwtService.generateToken(authentication);
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .toList();
        return ResponseEntity.ok(new LoginJwtResponse(username,roles,token));
    }
}