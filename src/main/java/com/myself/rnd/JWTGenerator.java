package com.myself.rnd;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@SpringBootApplication
@EnableScheduling
public class JWTGenerator {
    private static final Logger LOGGER = LogManager.getLogger(JWTGenerator.class);

    public static void main(String[] args) throws Exception {
        SpringApplication.run(JWTGenerator.class, args);
        LOGGER.debug("JECAP Currency Converted Service started...");

        String KeyId = "125037604453278520";
        String Audience = "domain.com";
        String Issuer = "kichuekta@domain";
        String Subject = "kichuekta@domain";
        String rsaPrivateKey = "bishalBishalCodeertyuiklmnbvcdfghjkoiuyt4wer89okmnbvfd3qaszxcvbnmki8765rfghjm";

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(KeyId)
                .keyUse(KeyUse.SIGNATURE)
                .generate();

        JWSHeader headers = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaJWK.getKeyID())
                .type(JOSEObjectType.JWT)
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(Subject)
                .issuer(Issuer)
                .audience(Audience)
                .issueTime(now)
                .expirationTime(new Date(new Date().getTime() + 3600000))
                .notBeforeTime(now)
                .build();

        SignedJWT signedJWT = new SignedJWT(headers, claimsSet);

        //JWSSigner signer = new RSASSASigner(rsaJWK);
        JWSSigner signer = new RSASSASigner(rsaJWK);
        signedJWT.sign(signer);

        String jwtToken = signedJWT.serialize();

        System.out.println(jwtToken);

        System.out.println("===========================================");

        RSAPrivateKey privateKey = getPrivateKey(rsaPrivateKey);

        JwtBuilder builder = Jwts.builder().setSubject(Subject)
                .setAudience(Audience)
                .setIssuedAt(now)
                .setNotBefore(now)
                .setExpiration(new Date(new Date().getTime() + 3600000))
                .signWith(SignatureAlgorithm.RS256, privateKey);

        String jwtToken2 = builder.compact();

        System.out.println("JWT Token:");
        System.out.println(jwtToken2);
    }

    private static RSAPrivateKey getPrivateKey(String rsaPrivateKeyStr) throws Exception {

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(convertToPKC8(rsaPrivateKeyStr));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(spec);
        System.out.println("GENERATED: " + privateKey);
        return privateKey;
    }

    private static byte[] convertToPKC8(String pkcs1) throws IOException {

        // b64 now contains the base64 "body" of the PEM-PKCS#1 file
        byte[] oldKey = Base64.getDecoder().decode(pkcs1.getBytes());

        // concatenate the mostly-fixed prefix plus the PKCS#1 data
        final byte[] prefix = {0x30, (byte) 0x82, 0, 0, 2, 1, 0, // SEQUENCE(lenTBD) and version INTEGER
                0x30, 0x0d, 6, 9, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 1, 1, 1, 5, 0, // AlgID for rsaEncryption,NULL
                4, (byte) 0x82, 0, 0}; // OCTETSTRING(lenTBD)
        byte[] newKey = new byte[prefix.length + oldKey.length];
        System.arraycopy(prefix, 0, newKey, 0, prefix.length);
        System.arraycopy(oldKey, 0, newKey, prefix.length, oldKey.length);
        // and patch the (variable) lengths to be correct
        int len = oldKey.length, loc = prefix.length - 2;
        newKey[loc] = (byte) (len >> 8);
        newKey[loc + 1] = (byte) len;
        len = newKey.length - 4;
        loc = 2;
        newKey[loc] = (byte) (len >> 8);
        newKey[loc + 1] = (byte) len;

        return newKey;

    }


}
