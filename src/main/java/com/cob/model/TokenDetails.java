package com.cob.model;

import lombok.Data;

import java.util.Date;

@Data
public class TokenDetails {
    private String token;
    private Date expireAt;
    private String issuer;
    private String role;
}
