package com.daniel.Main;

import org.junit.Test;
import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Date;
import java.util.HashMap;
import java.util.Map;

import io.jsonwebtoken.SignatureAlgorithm;
public class MyTest {
//    	assertEquals(5, result);

    @Test
    public void testSomething() throws NoSuchAlgorithmException {
        // Your test logic here
    	assertEquals(JwtsServer.getkeyPairs(), new HashMap<String, KeyPairInfo> ());
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
		 KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
		 KeyPair keypair = keyGenerator.generateKeyPair();

	     long time = System.currentTimeMillis() + 3600 * 60 * 1000L;
;
	     Date exp = new Date(time);
	     JwtsServer.secretKey = "NeedToUpdateEnvs";
    	KeyPairInfo testPair = new KeyPairInfo(keypair.getPublic(), keypair.getPrivate(), 1, exp);
    	assertEquals(testPair.getKid(), 1);
    	assertEquals(testPair.getExpiry(), exp);
    	assertEquals(testPair.getPrivateKey(), keypair.getPrivate());
    	assertEquals(testPair.getPublicKey(), keypair.getPublic());
    	AuthEndpoint authEndpoint = new AuthEndpoint();
	    String jwtJson = JwtsServer.generateJwksJson();
	    assertEquals("{\"keys\":[]}", jwtJson);
	    String token = AuthEndpoint.issueJwtToken(keypair, "TestKID", exp);
	    assert token.length() >=100 : " token is too short";
	    jwtJson = JwtsServer.generateJwksJson();
	    assert jwtJson.length() >= 20 : "jwtJson is shorter than expected";
	    KeyPair keypair2 = authEndpoint.generateKeyPair();
	    assert keypair2 != null : "keyPair cannot be null";
	    boolean isExp = authEndpoint.isExpiredParm(null);
	    assertEquals(false, isExp);
	    
	    Database.createNewDatabase("totally_not_my_privateKeys.db");
	    Database.loadKeyPairs(new HashMap<Integer, KeyPairInfo>(), "totally_not_my_privateKeys.db");
	    
	    String password = "testPW";
	   String testhash = Database.hashingPW(password); 
	   String testhash2 = Database.hashingPW(password); 

	   assertTrue(testhash.equals(testhash2));
	   long currTime = System.currentTimeMillis();
	   Database.updateAuthLogs("totally_not_my_privateKeys.db", "127.0.2.1", 1, currTime);
	   Database.updateUserDB("totally_not_my_privateKeys.db", "testName", "email@gmai.com", password, currTime);
	   try {
		JwtsServer.main(null);
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    }	
}