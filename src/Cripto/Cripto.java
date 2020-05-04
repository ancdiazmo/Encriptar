package Cripto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cripto {
	
	private static final String KEYSTOREPATH = "keystore.jceks";
	
    private SecretKey getEncryptionKey (String keyStorePath) {
    	
		KeyStore keyStore;
		
		try {
			keyStore = KeyStore.getInstance("JCEKS");
			char[] keyStorePassword = "12345".toCharArray();
			
			try(InputStream keyStoreData = new FileInputStream(keyStorePath)){
			    keyStore.load(keyStoreData, keyStorePassword);
			} 
			catch (Exception e) {}
			
	    	char[] keyPassword = "12345".toCharArray();
	    	KeyStore.ProtectionParameter entryPassword =
	    	        new KeyStore.PasswordProtection(keyPassword);
	    	KeyStore.SecretKeyEntry keyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("keyAlias", entryPassword);
	    	return keyEntry.getSecretKey();
		} 
		
		catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		} 
		
		return null;
    }
    
    public byte[] encrypt(byte[] value) throws Exception {
    	SecretKey encryptionKey = getEncryptionKey (KEYSTOREPATH);
        IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
        return cipher.doFinal(value);
    }

    public byte[] decrypt(byte[] value) throws Exception {
    	SecretKey encryptionKey = getEncryptionKey (KEYSTOREPATH);
        IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
        SecretKeySpec spec = new SecretKeySpec(encryptionKey.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, spec, iv);
        return cipher.doFinal(value);
    }
    
}
