package com.daniel.Main;


import static org.junit.Assert.assertNotNull;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class Database {
	
	/*
	 GPT prompt:
	 how to create table in sqlite in java

something like 
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
	 */
	public static String hashingPW(String password) {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id);
        builder.withVersion(Argon2Parameters.ARGON2_VERSION_13);
        builder.withMemoryAsKB(65536); // Memory in kilobytes
        builder.withIterations(2);
        byte[] salt = Base64.getDecoder().decode("R3Ebs5e3C8N+zx4hYcvEjg==");//in real work, will need to generate random and store it in DB
        builder.withSalt(salt);
        builder.withParallelism(1);
        
        Argon2Parameters params = builder.build();
        
        //Hash the password
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        
        byte[] passwordBytes = password.getBytes();
        byte[] hash = new byte[32]; //argon2 output length 32
        generator.generateBytes(passwordBytes, hash);
        return Base64.getEncoder().encodeToString(hash);
	}
	
    public static void createNewDatabase(String fileName) {

    	  Connection connection = null;
          Statement statement = null;

          try {
              // SQLite database file location
              // JDBC URL for SQLite
              String url = "jdbc:sqlite:" + fileName;

              // Establish a connection to the database
              connection = DriverManager.getConnection(url);
              assertNotNull(connection);
              // Create a Statement object
              statement = connection.createStatement();
              assertNotNull(statement);

              // Create the 'keys' table
              String createTableSQL = "CREATE TABLE IF NOT EXISTS keys (" +
                      "kid INTEGER PRIMARY KEY AUTOINCREMENT," +
                      "key BLOB NOT NULL," +
                      "exp INTEGER NOT NULL" +
                      ")";
              
              // Execute the SQL statement to create the table
              statement.execute(createTableSQL);
              
              System.out.println("Table 'keys' created successfully.");
              
              createTableSQL = "CREATE TABLE IF NOT EXISTS users("
              		+ "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
             		+ "    username TEXT NOT NULL UNIQUE,"
              		+ "    password_hash TEXT NOT NULL,"
              		+ "    email TEXT UNIQUE,"
              		+ "    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
              		+ "    last_login TIMESTAMP"
              		+ ")";
              
              statement.execute(createTableSQL);
              System.out.println("Table 'users' created successfully.");
              
              createTableSQL = "CREATE TABLE IF NOT EXISTS auth_logs("
              		+ "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
              		+ "    request_ip TEXT NOT NULL,"
              		+ "    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
              		+ "    user_id INTEGER,"
              		+ "    FOREIGN KEY(user_id) REFERENCES users(id)"
              		+ ");";
                
                statement.execute(createTableSQL);
                System.out.println("Table 'auth_logs' created successfully.");

          } catch (SQLException e) {
              e.printStackTrace();
          } finally {
              try {
                  if (statement != null) {
                      statement.close();
                  }
                  if (connection != null) {
                      connection.close();
                  } 
              } catch (SQLException e) {
                  e.printStackTrace();
              }
          }
    }
    
    private static Connection connect(String dbFile) {
        // SQLite connection string
        String url = "jdbc:sqlite:" + dbFile;
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(url);
            assertNotNull(conn);

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        assertNotNull(conn);
        return conn;
    }


    
    public static byte[] PrivateKeyToBLOB( PrivateKey privateKey , String secretKey){ //with AES
    	 // Serialize the KeyPair to a byte array
    	PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
    	KeyFactory keyFactory =null;
    	byte[] rs= null;
    	try {
    		keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm());
    		byte[] privateKeybytes = keyFactory.generatePrivate(pkcs8KeySpec).getEncoded();
    		
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    	assertNotNull(cipher);
	    	byte[] keyBytes = secretKey.getBytes("UTF-8");
	    	Key secretKeySpec = new SecretKeySpec(keyBytes, "AES");
	    	cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
	    	byte[] encrytedBytes = cipher.doFinal(privateKeybytes);
	    	rs = Base64.getEncoder().encodeToString(encrytedBytes).getBytes("UTF-8");	    
    		
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	return rs;
    }
    
    
    public static PrivateKey byteToPrivateKey(byte[] encrytedKeyBytes, String secretKey) {
    	PrivateKey privateKey = null;
    	try {
    		String encrytedPrivateKey = new String(encrytedKeyBytes, "UTF-8");
    		
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    	assertNotNull(cipher);
	    	byte[] keyBytes = secretKey.getBytes("UTF-8");
	    	Key secretKeySpec = new SecretKeySpec(keyBytes, "AES");
	    	cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);	    	
	    	
	    	byte[] encryptedBytes = Base64.getDecoder().decode(encrytedPrivateKey);
	    	byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedBytes);
            privateKey = keyFactory.generatePrivate(keySpec);
	    	
		} catch (Exception e) {
			// TODO: handle exception
		}
    	
    	
    	return privateKey;
    	
    }
    
    
    
    public static PublicKey getPublicKeyFromPrivate( PrivateKey privateKey ) {
    	PublicKey key = null;
    	try {
    		RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
    		RSAPublicKeySpec publickeySpec = new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(), 
    				rsaPrivateCrtKey.getPublicExponent());
    		
    		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    		key = keyFactory.generatePublic(publickeySpec);
    	} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	return key;
    }
    
    
    //https://www.sqlitetutorial.net/sqlite-java/select/
    public static void loadKeyPairs(Map<Integer, KeyPairInfo> keyPairs, String dbfile) {
    	String sql = "SELECT kid, key, exp FROM keys";
    	Connection conn = connect(dbfile);
    	
    	try {
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(sql);
            assertNotNull(stmt);
            assertNotNull(rs);

		     // loop through the result set
            while (rs.next()) {
                int kid = rs.getInt("kid");
                byte[] serKey = rs.getBytes("key");
                long exp = rs.getLong("exp") * 1000L; //second to ms
                assertNotNull(serKey);
                PrivateKey privatekey = Database.byteToPrivateKey(serKey, JwtsServer.secretKey);
                PublicKey publicKey = Database.getPublicKeyFromPrivate(privatekey);
                assertNotNull(privatekey);

                JwtsServer.getkeyPairs().put(kid, new KeyPairInfo(publicKey, privatekey, kid, new Date(exp) ));//load data 
                JwtsServer.maxKid = Math.max(kid, JwtsServer.maxKid);
            }
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally {
		    if (conn != null) {
	            try {
	                conn.close();
	            } catch (SQLException e) {
	                e.printStackTrace();
	            }
	        }
		}
    	
    }
    
    public static void updateKeyPairDB(String dbfile, KeyPairInfo info) {
    	System.out.println("updateKeyPair called");
    	// Assuming you have a 'keypair_table' with a BLOB column named 'keypair_blob' and a unique 'kid' column
    	String insertQuery = "INSERT OR REPLACE INTO keys (kid, key, exp) VALUES (?, ?, ?)";
    	Connection conn = connect(dbfile);
    	try {
            assertNotNull(conn);

    		PreparedStatement statement = conn.prepareStatement(insertQuery);
    		byte[] privatekeyBytes = PrivateKeyToBLOB(info.getPrivateKey(),  JwtsServer.secretKey);
            assertNotNull(statement);
            assertNotNull(privatekeyBytes);

    	    // Set the values for the 'kid' and 'keypair_blob' columns
            statement.setInt(1, info.getKid());
    	    statement.setBytes(2, privatekeyBytes);
    	    statement.setLong(3, info.getExpiry().getTime() / 1000L); //JWT uses seconds not ms

    	    statement.executeUpdate();
    	    System.out.println("KeyPair size: " + JwtsServer.getkeyPairs().size() );
    	    System.out.println("update Keypair DB done");

    	}catch (Exception e){
    		e.printStackTrace();
    	}finally {
    	    if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
		} 	
    }
 
    public static void updateUserDB(String dbfile, String username, String email, String password, long lastLogin) {
    	System.out.println("updateUserDB called");
    	
        Date time = new Date(lastLogin);
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
//'2023-11-01 14:30:00'
        String format = formatter.format(time);
        
    	String insertQuery = "INSERT OR REPLACE INTO users (username, email, password_hash, last_login) VALUES "
    			+ "(?, ?, ?, ?);";
    	Connection conn = connect(dbfile);
    	try {
    	
            assertNotNull(conn);

    		PreparedStatement statement = conn.prepareStatement(insertQuery);
            assertNotNull(statement);

    	    // Set the values for the 'kid' and 'keypair_blob' columns
            statement.setString(1, username);
    	    statement.setString(2, email);
    	    statement.setString(3, Database.hashingPW(password) ); //save hashed password
    	  //  Timestamp lasttime =  new Timestamp(lastLogin);
            //Timestamp eventTime = Timestamp.valueOf("2023-11-01 15:30:00");
    	       


    	    statement.setString(4, format);
    	    assertNotNull(format);
           // statement.setTimestamp(4, lasttime);
    	    statement.executeUpdate();
    	//    System.out.println("updateUserDB done");
    	}catch (Exception e){
    		e.printStackTrace();
    	}finally {
    	    if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
		}
    }
    
    public static int getUserIDfromDB(String dbfile, String username) {
    //	System.out.println("updateKeyPair called");
    	
    	Connection conn = connect(dbfile);

    	
    	try {
            assertNotNull(conn);
            String selectQuery = "SELECT id FROM users WHERE username = ?";
    		PreparedStatement statement = conn.prepareStatement(selectQuery);
            assertNotNull(statement);

    	    // Set the values for the 'kid' and 'keypair_blob' columns
            statement.setString(1, username);
            
            // Execute the query and retrieve the result
            ResultSet resultSet = statement.executeQuery();

            // Check if a result was found
            if (resultSet.next()) {
                // Retrieve the id from the result set
                int id = resultSet.getInt("id");
                return id;
            } 
    	}catch (Exception e){
    		
    	}finally {
		    if (conn != null) {
	            try {
	                conn.close();
	            } catch (SQLException e) {
	                e.printStackTrace();
	            }
	        }
		}
		return -1;   //return not found	
    }
    
    public static void updateAuthLogs(String dbfile, String IP, int userID, long currntTimeMS) {
    	System.out.println("updateAuthLogs called");
    	String insertQuery = "INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)";
    	long start = System.currentTimeMillis();
    	
    	Connection conn = connect(dbfile);
    
    	long end = System.currentTimeMillis();
    	System.out.println("Connect took: " + (end-start));
    	try {
            assertNotNull(conn);

            start = System.currentTimeMillis();
    		PreparedStatement statement = conn.prepareStatement(insertQuery);
            assertNotNull(statement);
            end = System.currentTimeMillis();
        	System.out.println("Prepare took: " + (end-start));

            Date time = new Date(currntTimeMS);
            SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
//'2023-11-01 14:30:00'
            String format = formatter.format(time);
   
//INSERT OR REPLACE INTO users (username, email, password_hash, last_login) VALUES ("test23", "asdf@gam", "asdfasfs", '2023-11-01 14:30:00');
          //  Timestamp timeStamp = new Timestamp(currntTimeMS);// not works


    	    // Set the values for the 'kid' and 'keypair_blob' columns
            statement.setString(1, IP);
    	    statement.setString(2, format);
        //    statement.setTimestamp(2, timeStamp);
    	    statement.setInt(3, userID ); //user id
            System.out.println("log statement: " + statement.toString());
    	    
            start = System.currentTimeMillis();
    	    statement.executeUpdate();
    	    end = System.currentTimeMillis();
        	System.out.println("excute took: " + (end-start));

    	    
        	System.out.println("updateAuthLogs done");

    	}catch (Exception e){
    		e.printStackTrace();
    	}finally {
		    if (conn != null) {
	            try {
	                conn.close();
	            } catch (SQLException e) {
	                e.printStackTrace();
	            }
	        }
		}
    }
    
    
}
