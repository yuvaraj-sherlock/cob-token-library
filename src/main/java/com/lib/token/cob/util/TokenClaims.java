package com.lib.token.cob.util;

import lombok.Getter;

@Getter
public enum TokenClaims {
    ROLE("role"),
    ISSUER("COB-PORTAL");

    private final String claimName;

    TokenClaims(String claimName) {
        this.claimName = claimName;
    }

    @Override
    public String toString() {
        return claimName;
    }

}
