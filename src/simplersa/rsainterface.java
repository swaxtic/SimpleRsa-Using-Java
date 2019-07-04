/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simplersa;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author dip(A11.2016.09807)
 */
public class rsainterface {
    
    public static void main(String[] args) throws Exception {
	
		byte[] data = "hello cryptography".getBytes();
		
		Rsa.generateKey("./public.key", "./private.key");		

		PublicKey publicKey = Rsa.getPublicKey("./public.key");

		byte[] encrypted = Rsa.encrypt(publicKey, data);		

		PrivateKey privateKey = Rsa.getPrivateKey("./private.key");

		byte[] decrypted = Rsa.decrypt(privateKey, encrypted);		

		System.out.println("original: " + new String(data));
		System.out.println("encrypted: " + new String(encrypted));
		System.out.println("decrypted: " + new String(decrypted));

	}
}
