package com.daniel.Main;

import static org.junit.Assert.assertNotNull;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

//Handler for /jwks endpoint
	//ChatGPT prompt: what should I write in JWKSHandler 

	public class RegisterEndPoint implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {

			if ("POST".equals(exchange.getRequestMethod())) {
				BufferedReader reader =
						new BufferedReader(new InputStreamReader(exchange.getRequestBody(), "UTF-8"));
				StringBuilder requestBody = new StringBuilder();
				String line;
				
				while( (line = reader.readLine()) != null) {
					requestBody.append(line);
				}
				reader.close();
				
				ObjectMapper objectMapper = new ObjectMapper();
				JsonNode jsonNode = objectMapper.readTree(requestBody.toString());
				String username = jsonNode.get("username").asText();
				String email = jsonNode.get("email").asText();
				System.out.println("Reg: user:" + username + " email:" + email);
				
			//TODO store data to db with hashed password
				String password = UUID.randomUUID().toString();
				assertNotNull(password);
				long currTime = System.currentTimeMillis();
	            // Convert the password JSON object to a string	
				Database.updateUserDB("totally_not_my_privateKeys.db", username, email, password, currTime);
			//	long end = System.currentTimeMillis();
			//	System.out.println("took for user db: " + (end - currTime));
				Map<String, String> jsonResponse = new HashMap<String, String>();
				jsonResponse.put("password", password);
				// Use Jackson to serialize the Map to JSON
				
				String passwordInfo = objectMapper.writeValueAsString(jsonResponse);//json of password
	        //{"password": "$UUIDv4"}.    
	            assertNotNull(passwordInfo);
	           // Send response with a status code and the password JSON in the response body
	            exchange.getResponseHeaders().set("Content-Type", "application/json");

	            System.out.println("new pw: " + passwordInfo);
	            byte[] responseBytes = passwordInfo.getBytes("UTF-8");
	            exchange.sendResponseHeaders(201, responseBytes.length);
	            OutputStream os = exchange.getResponseBody();
	            os.write(responseBytes);
	            os.close();
	            exchange.close();
			} else {
				// Method not allowed
				System.out.println("Method for JWT: " + exchange.getRequestMethod());
		
				exchange.sendResponseHeaders(405, -1);
				exchange.getResponseBody().close();
				exchange.close();
			}
		}
	}	