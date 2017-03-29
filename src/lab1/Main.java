package lab1;

import java.nio.charset.StandardCharsets;

import java.security.*;
import javax.crypto.*;

public class Main {
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, 
	InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		/** 2.2.1 Preparation **/
		/***********************/
		
		Person person1 = new Person("Alex", "Izegem", "123456789");
		Person person2 = new Person("Mark", "Harelbeke", "987654321");
		Person person1Fake = new Person("Alex2", "Izegem", "123456789");
		
		byte[] person1Bytes = person1.getBytes();
		byte[] person2Bytes = person2.getBytes();
		byte[] person1FakeBytes = person1Fake.getBytes();
		
		// 2.2.2 Hashing / Message Digest
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] person1Hash = sha256.digest(person1Bytes);
		byte[] person1FakeHash = sha256.digest(person1FakeBytes);

		System.out.println("Person 1 SHA-256 Hash   : " + javax.xml.bind.DatatypeConverter.printHexBinary(person1Hash));
		System.out.println("Person 2 SHA-256 Hash   : " + javax.xml.bind.DatatypeConverter.printHexBinary(person1FakeHash));
		
	    String message = "Hello this is a message!";	
	    byte[] messageBytes =  message.getBytes(StandardCharsets.UTF_8);
		
		/** 2.2.3 Symmetric Encryption **/
		/********************************/
	    
		// Step 1 : Generate a key
	    KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES");
	    aesKeyGenerator.init(128);
	    SecretKey aesKey = aesKeyGenerator.generateKey();
	    
	    // Step 2: Encrypt using the key 
	    Cipher aesCipher = Cipher.getInstance("AES");
	    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
	    
        byte[] aesEncryptedMessageBytes = aesCipher.doFinal(messageBytes);
        
        // Step 3: Decrypt using the same key
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] aesDecryptedMessageBytes = aesCipher.doFinal(aesEncryptedMessageBytes);
        String aesDecryptedMessage = new String(aesDecryptedMessageBytes, StandardCharsets.UTF_8);
        
        // Step 4: Compare
        System.out.println("AES Original message    : " + message);
        System.out.println("AES Decrypted message   : " + aesDecryptedMessage);
        
        /** 2.2.4 Asymmetric Encryption **/
		/*********************************/
        
		// Step 1 : Generate a public and private key
        KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair rsaKeyPair = rsaKeyPairGenerator.generateKeyPair();
        PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();
        PublicKey rsaPublicKey = rsaKeyPair.getPublic();
        
        // Step 2: Encrypt using the public key
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        byte[] rsaEncryptedMessageBytes = rsaCipher.doFinal(messageBytes);
        
        // Step 3: Decrypt using the private key
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] rsaDecryptedMessageBytes = rsaCipher.doFinal(rsaEncryptedMessageBytes);
        String rsaDecryptedMessage = new String(rsaDecryptedMessageBytes, StandardCharsets.UTF_8);
        
        System.out.println("RSA Original message    : " + message);
        System.out.println("RSA Decrypted message   : " + rsaDecryptedMessage);
        
        /** 2.2.5 Digital signatures **/
        /******************************/
        
        // Step 1: Generate public / private key
        // We will reuse the RSA private / public key pair from above
        
        // Step 2: Generate signatures, one to sign and one to verify
        Signature rsaSignatureToSign = Signature.getInstance("SHA1withRSA");
        Signature rsaSignatureToVerify = Signature.getInstance("SHA1withRSA");
        
        // Step 3: Sign the person2 bytes        
        rsaSignatureToSign.initSign(rsaPrivateKey);
        rsaSignatureToSign.update(person2Bytes);
        byte[] signature = rsaSignatureToSign.sign();
        System.out.println("SHA1 + RSA Signature    : " + javax.xml.bind.DatatypeConverter.printHexBinary(signature));
        
        // Step 4: Verify the signature
        rsaSignatureToVerify.initVerify(rsaPublicKey);
        rsaSignatureToVerify.update(person2Bytes);
        boolean isValidSignature = rsaSignatureToVerify.verify(signature);
        System.out.println("Is valid signature      : " + isValidSignature);       
        
	}
	
	
}
