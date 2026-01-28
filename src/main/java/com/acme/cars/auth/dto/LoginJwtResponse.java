package com.acme.cars.auth.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginJwtResponse {
    private String username;
    private List<String> roles;
    private String token;
    }
