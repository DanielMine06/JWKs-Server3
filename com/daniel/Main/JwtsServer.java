package com.daniel.Main;


import com.sun.net.httpserver.HttpServer;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import static org.junit.Assert.assertNotNull;

import java.net.InetSocketAddress;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.sql.Connection;
import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.crypto.Data;

public class JwtsServer {

	
	private static Map<Integer, KeyPairInfo> keyPairs = new HashMap<>();
	public static int maxKid = 0;
	public static String secretKey;
	public static TimeWindowRateLimiter rateLimiter;

	public static void main(String[] args) throws Exception {
		// Add BouncyCastle as a security provider

		String dbFile = "totally_not_my_privateKeys.db";	
		secretKey = System.getenv("NOT_MY_KEY");
		if(secretKey == null) {
			secretKey = "NeedToUpdateEnvs"; //8 *n legnth
		}
		
		Database.createNewDatabase(dbFile);
		
		Database.loadKeyPairs(keyPairs, dbFile);
		


		System.out.println("keyPairs size " + keyPairs.size());
		AuthEndpoint authEndPoint = new AuthEndpoint();
		int expired =0;
		int notExpired = 0;
		
		
		for(KeyPairInfo info : keyPairs.values()) {
			if(info.getExpiry().after(new Date(60 * 1000L * 60 + System.currentTimeMillis()))) {
				notExpired++;
			}else if( info.getExpiry().before(new Date(System.currentTimeMillis()) ) ) {
				expired++;
			}
		}
		

		//Security.addProvider(new BouncyCastleProvider());
		if(expired < 1) { //need to create token both expired and not expired
			System.out.println("No expired key found, creating that");
			KeyPair kp = authEndPoint.generateKeyPair();
			String username = "userABC";
				Date expTime = new Date(24 * 60 * 60 * 1000L);
				AuthEndpoint.issueJwtToken(kp, username, expTime);	
		}
		
		if(notExpired < 1) {
			System.out.println("No non-expired key found, creating that");

			KeyPair kp = authEndPoint.generateKeyPair();
			Date expTimeNotExpire = new Date(System.currentTimeMillis() + 24* 60 * 60 * 1000);
			String username = "userABC";
			AuthEndpoint.issueJwtToken(kp, username, expTimeNotExpire);		
		}
		
		System.out.println("DB load done");
		
		// Create an HTTP server on port 8080
		HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

		// Create JWKS endpoint
		server.createContext("/.well-known", new JWKSEndpoint());

		// Create auth endpoint
		server.createContext("/auth", authEndPoint);

		server.createContext("/register", new RegisterEndPoint() );

		server.setExecutor(null); // Default executor
		server.start();
		rateLimiter = new TimeWindowRateLimiter();	
	    
		/*for(int i=0; i<30; i++) {
	            if(rateLimiter.allowRequest()) {
	                System.out.println("success");
	            }else {
	                System.out.println("Rate exceed");
	            }

	            Thread.sleep(50);
	        }
	        */
	}


	public static Map<Integer, KeyPairInfo> getkeyPairs() {
		return keyPairs;
	}
	

	/* ChatGPT prompt : 
	 how to make json for list of tokens with kids
	json format should be something like below:

	{
	        "keys" :
	        [
	                {
	                        "e" : "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0...",
	                        "kid" : "0", 
	                        "kty" : "RSA",
	                        "n" : "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0..."
	                }
	        ]
	}
	*/
	public static String generateJwksJson() {
	    // Create a JSON array to hold the keys
	    JSONArray keysArray = new JSONArray();

	    // Get the current time in seconds
	    long currentTimeSeconds = System.currentTimeMillis() / 1000;

	    // Iterate through the keyPairs and add unexpired keys to the JSON array
	    for (Map.Entry<Integer, KeyPairInfo> entry : keyPairs.entrySet()) {
	        KeyPairInfo keyPairInfo = entry.getValue();
	        if (keyPairInfo.getExpiry().getTime() / 1000 > currentTimeSeconds) {
	            JSONObject keyObject = new JSONObject();
	            try {
		            keyObject.put("kid", keyPairInfo.getKid()+ "" );
					keyObject.put("kty", "RSA");
					RSAPublicKey publicKey = (RSAPublicKey) keyPairInfo.getPublicKey();
			        keyObject.put("n", Base64.getUrlEncoder().encodeToString(publicKey.getModulus().toByteArray()));
		            keyObject.put("e", Base64.getUrlEncoder().encodeToString(publicKey.getPublicExponent().toByteArray()));
		            keyObject.put("use", "sig"); // Indicates the key is used for signature verification

				} catch (JSONException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	    
	            // Add the keyObject to the keysArray
	            keysArray.put(keyObject);
	        }
	    }

	    // Create the JWKS JSON object
	    JSONObject jwksObject = new JSONObject();
	    try {
			jwksObject.put("keys", keysArray);
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	    // Convert the JWKS JSON object to a string
	    System.out.println( jwksObject.toString());
	    return jwksObject.toString();
	}

	
}