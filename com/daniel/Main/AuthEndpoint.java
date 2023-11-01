package com.daniel.Main;


import static org.junit.Assert.assertNotNull;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

// Handler for /auth endpoint
//ChatGPT Prompt: how to get public and private key in code

public class AuthEndpoint implements HttpHandler {
	
	public KeyPair generateKeyPair() {
		KeyPairGenerator keyGenerator = null;
		try {
			keyGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();

		}
		keyGenerator.initialize(2048);
		KeyPair kp = keyGenerator.generateKeyPair();
		return kp;
	
	}
	public boolean isExpiredParm(String para) {
		return para != null && para.contains("expired=true");
	}
	
	@Override
	public void handle(HttpExchange exchange) throws IOException {
		String IP = exchange.getRemoteAddress().getAddress().getHostAddress();
		assertNotNull(JwtsServer.rateLimiter);
		
		if(!JwtsServer.rateLimiter.allowRequest()) {
			System.out.println("Too many request");
			exchange.sendResponseHeaders(429, -1); //send message too many request
			exchange.close();
			
			return; //return rate limited
		}else {
			System.out.println("Okay to request");
		}


		String para = exchange.getRequestURI().getQuery();

	//	System.out.println("para in auth: " + para);
		
		// this portion gives 1 points (start)
		// Create a BufferedReader to read the content

		// above portion gives 1 points (end)
		InputStream inputStream = exchange.getRequestBody();

		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

		// Read and print each line of the content
		StringBuilder requestbody = new StringBuilder();
		String line;
		while ((line = reader.readLine()) != null) {
			requestbody.append(line);
		}

		// Close the reader and the input stream
		reader.close();
		inputStream.close();
				

		if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
			// https://www.viralpatel.net/java-create-validate-jwt-token/
			KeyPair kp = generateKeyPair();
			ObjectMapper objectMapper = new ObjectMapper();
			long currentTime = System.currentTimeMillis();
			JsonNode jsonNode = objectMapper.readTree(requestbody.toString());
			String username = jsonNode.get("username").asText();
			assertNotNull(username);
				
			int userID = Database.getUserIDfromDB("totally_not_my_privateKeys.db", username);
		//	System.out.println("username: " + username + "   IP:" + IP + " userID="+ userID);

			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;

			String jwtToken;
			if (isExpiredParm(para)) {
				//System.out.println("expired para is true");
				KeyPairInfo info = null;
				
				for(KeyPairInfo entry : JwtsServer.getkeyPairs().values()) {
					if(entry.getExpiry().before(new Date(System.currentTimeMillis()))) {
						info = entry;
						break;
					}
				}
				
				if(info == null) {
					System.out.println("No expired key found, creating that");

					Date expTime = new Date(System.currentTimeMillis() - (24 * 60 * 60 * 1000L));

					jwtToken = issueJwtToken(kp, username, expTime);
				}else {
					jwtToken = Jwts.builder().setHeaderParam("alg", "RS256") // Header with algorithm
							.setHeaderParam("typ", "JWT") // Header with token type
							.setHeaderParam("kid", info.getKid() + "")
							.setSubject("userABC").signWith(signatureAlgorithm, info.getPrivateKey()).
							setExpiration(info.getExpiry()).compact();		
					assertNotNull(jwtToken);
				}

			} else {
			//	System.out.println("expired para is false");

				KeyPairInfo info = null;
				
				for(KeyPairInfo entry : JwtsServer.getkeyPairs().values()) {
					if(entry.getExpiry().after(new Date(System.currentTimeMillis() + 60 * 1000L))) {
						info = entry;
						break;
					}
				}
				
				if(info == null) {
					System.out.println("No non-expired key found, creating that");

					Date expTime = new Date(System.currentTimeMillis() + 60 * 60 * 1000);

					jwtToken = issueJwtToken(kp, username, expTime);

				}else {

					jwtToken = Jwts.builder().setHeaderParam("alg", "RS256") // Header with algorithm
							.setHeaderParam("typ", "JWT") // Header with token type
							.setHeaderParam("kid", info.getKid() + "")
							.setSubject("userABC").signWith(signatureAlgorithm, info.getPrivateKey()).
							setExpiration(info.getExpiry()).compact();					
				}
				

			}
			System.out.println("issued token\n");
			// String response = "JWT Token: " + jwtToken;
			long start = System.currentTimeMillis();
			Database.updateAuthLogs("totally_not_my_privateKeys.db", IP, userID, currentTime);
			long end = System.currentTimeMillis();
			System.out.println("took for log db: " + (end - start));
			
			exchange.sendResponseHeaders(200, jwtToken.getBytes().length);
			System.out.println("response auth: " + jwtToken);
			OutputStream output = exchange.getResponseBody();
			output.write(jwtToken.getBytes());
			output.flush();
			exchange.close();
			

			//System.out.println("End Auth\n");

		} else {
			// Method not allowed
			exchange.sendResponseHeaders(405, -1);
			exchange.close();

		//	System.out.println("End Auth\n");

		}
	}
	
	// Create a JWT token using the selected private key
	public static String issueJwtToken(KeyPair keypair, String subject, Date expTime) {

		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
		   RSAPublicKey publicKey = (RSAPublicKey) keypair.getPublic();
	       RSAPrivateKey privateKey = (RSAPrivateKey) keypair.getPrivate();
	//	byte[] scretKeyBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
	//	Key signingKey = new SecretKeySpec(scretKeyBytes, signatureAlgorithm.getJcaName());
		//System.out.println("Called issueJwtToken");
		
//ChatGPT prompt: issue expired jwt token in Java
		try {
			int kid = JwtsServer.maxKid + 1;
			
			String jwtToken = Jwts.builder().setHeaderParam("alg", "RS256") // Header with algorithm
					.setHeaderParam("typ", "JWT") // Header with token type
					.setHeaderParam("kid", kid + "")
					.setSubject(subject).signWith(signatureAlgorithm, privateKey).setExpiration(expTime).compact();
//.setHeaderParam("kid", kid) is neccessary
			KeyPairInfo pairInfo = new KeyPairInfo(keypair.getPublic(), keypair.getPrivate(),kid , expTime);
			JwtsServer.getkeyPairs().put(pairInfo.getKid(), pairInfo);
			Database.updateKeyPairDB("totally_not_my_privateKeys.db", pairInfo);
			JwtsServer.maxKid = JwtsServer.maxKid + 1;
			System.out.println("Generated JWT Token: " + jwtToken);
			return jwtToken;
		} catch (Exception e) {
			System.err.println("Error generating JWT Token: " + e.getMessage());
			e.printStackTrace();
			return null; // or handle the error as needed
		}

	}


	
}
