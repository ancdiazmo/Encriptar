package Cripto;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CriptoGenerarKeyStore {
	
	public CriptoGenerarKeyStore () {
		try {
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(null,"12345".toCharArray());
			
			SecretKey secretKey = generateKey();
			KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
			
			KeyStore.ProtectionParameter entryPassword = 
					new KeyStore.PasswordProtection("12345".toCharArray());
			
			keyStore.setEntry("keyAlias", secretKeyEntry, entryPassword);
			
			try (FileOutputStream keyStoreOutputStream = new FileOutputStream("keystore.jceks")) {
			    keyStore.store(keyStoreOutputStream, "12345".toCharArray());
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		} 

	}
	
    private SecretKey generateKey() throws NoSuchAlgorithmException {
    	KeyGenerator keyGenerator = KeyGenerator.getInstance ("AES");
    	SecureRandom secureRandom = new SecureRandom ();
    	int keyBitSize = 128;
    	keyGenerator.init (keyBitSize, secureRandom);
    	SecretKey secretKey = keyGenerator.generateKey ();
    	return secretKey;
    }

}
