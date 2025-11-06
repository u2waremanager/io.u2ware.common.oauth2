package io.u2ware.common.oauth2.crypto;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


class CryptoTests {

	public static void main(String[] args) {

		Log logger = LogFactory.getLog(CryptoTests.class);





		// MockMvcRestDocs d = new MockMvcRestDocs() {};

		// mvc.perform(d.GET("/actuator/health")).andDo(d.print()).andExpect(d.is2xx());

		// mvc.perform(d.GET("/actuator/info")).andDo(d.print()).andExpect(d.is2xx());

		// mvc.perform(d.GET("/actuator/env")).andDo(d.print()).andExpect(d.is2xx());

		// mvc.perform(d.GET("/actuator/env/PATH")).andDo(d.print()).andExpect(d.is2xx());


		// try{
		// 	SecretKey key1 = CryptoKeyGenerator.generateAes();

		// 	String plainText = "Hello World";
		// 	String encryptedText1 = CryptoEncryptor.encrypt(plainText, key1);
		// 	System.out.println("cipherText1: " + encryptedText1);
	
		// 	String decryptedText1 = CryptoEncryptor.decrypt(encryptedText1, key1);
		// 	System.out.println("plainText1: " + decryptedText1);
	
		// 	// SecretKey key2 = CryptoKeyGenerator.generateAes();
		// 	// String decryptedText2 = CryptoKeyEncryptor.decrypt(encryptedText1, key2); //->Error
		// 	// System.out.println("plainText2: " + decryptedText2);

		// 	///////////////////////////////
		// 	//
		// 	///////////////////////////////
		// 	Path path1 = CryptoKeyStore.save(Paths.get("mykey1"), key1);
		// 	System.err.println(Files.exists(path1));
		// 	System.err.println(Files.size(path1));
		// 	System.err.println(path1.toFile().getAbsolutePath());


		// 	SecretKey key11 = CryptoKeyStore.load(path1, "AES");
		// 	String decryptedText11 = CryptoEncryptor.decrypt(encryptedText1, key11);
		// 	System.out.println("plainText11: " + decryptedText11);
		// 	System.out.println("plainText11: " + key11.hashCode());
		// 	System.out.println("plainText11: " + key1.hashCode());

		// 	Path path2 = CryptoKeyStore.save(Paths.get("mykey2"), key1, "mypass");
		// 	System.err.println(Files.exists(path2));
		// 	System.err.println(Files.size(path2));
		// 	System.err.println(path2.toFile().getAbsolutePath());


		// 	SecretKey key12 = CryptoKeyStore.load(path2, "??", "mypass");
		// 	String decryptedText12 = CryptoEncryptor.decrypt(encryptedText1, key12);
		// 	System.out.println("plainText12: " + decryptedText12);
		// 	System.out.println("plainText12: " + key12.hashCode());
		// 	System.out.println("plainText12: " + key1.hashCode());
	
		// }catch(Exception e){
		// 	e.printStackTrace();
		// }


		// SecretKey key1 = CryptoKeyGenerator.generateAes();
		// Path path2 = CryptoKeyStore.save(Paths.get(ClassUtils.getShortName(CryptoConverter.class)), key1, CryptoConverter.class.getName());


		// ClassPathResource r = new ClassPathResource(ClassUtils.getShortName(CryptoConverter.class), CryptoConverter.class);
		// logger.info(r.exists());
		// logger.info(r.getURI());



		// try{
		// 	JoseEncryptor encryptor1 = new JoseEncryptor(JoseKeyGenerator.generateRsa());
		// 	Jwt jwt1 = encryptor1.encrypt((claims)->{claims.put("a", "a");});
		
		// 	logger.info(jwt1);
		// 	logger.info(jwt1.getClaims());

		// 	Jwt jwt2 = encryptor1.decrypt(()->{return jwt1.getTokenValue();});
		// 	logger.info(jwt2);
		// 	logger.info(jwt2.getClaims());

		// 	// JoseEncryptor encryptor2 = new JoseEncryptor(JoseKeyGenerator.generateRsa());
		// 	// Jwt jwt3 = encryptor2.decrypt(()->{return jwt1.getTokenValue();});//->Error
		// 	// logger.info(jwt3);
		// 	// logger.info(jwt3.getClaims());

		// }catch(Exception e){
		// 	e.printStackTrace();

		// }
	}

}
