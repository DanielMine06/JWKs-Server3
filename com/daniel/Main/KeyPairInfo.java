package com.daniel.Main;


import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class KeyPairInfo {
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final int kid;
    private final Date expiry;

    public KeyPairInfo(PublicKey publicKey, PrivateKey privateKey, int kid, Date expiry) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.kid = kid;
        this.expiry = expiry;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public int getKid() {
        return kid;
    }

    public Date getExpiry() {
        return expiry;
    }
}
