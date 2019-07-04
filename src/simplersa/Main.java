/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simplersa;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import javax.swing.JOptionPane;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

/**
 *
 * @author dip(A11.2016.09807)
 */
public class Main extends javax.swing.JFrame {

    /**
     * Creates new form Main
     */
    public Main() {
        initComponents();
    }
         String hasildekrip;
         /**
	 * The constant that denotes the algorithm being used.
	 */
	private static final String algorithm = "RSA";	
	
	/**
	 * The private constructor to prevent instantiation of this object.
	 */

	/**
	 * The method that will create both the public and private key used to encrypt and decrypt the data.
	 * 
	 * @param publicKeyOutput
	 * 		The path of where the public key will be created.
	 * 
	 * @param privateKeyOutput
	 * 		The path of where the private key will be created.
	 * 
	 * @return {@code true} If this operation was successful, otherwise {@code false}.
	 */
	public static boolean generateKey(String publicKeyOutput, String privateKeyOutput) {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
			keyGen.initialize(2048);

			final KeyPair key = keyGen.generateKeyPair();

			try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(new File(publicKeyOutput)))) {
				dos.write(key.getPublic().getEncoded());
			}

			try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(new File(privateKeyOutput)))) {
				dos.write(key.getPrivate().getEncoded());
			}
			
			return true;

		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
}

	/**
	 * The method that will encrypt an array of bytes.
	 * 
	 * @param key
	 * 		The public key used to encrypt the data.
	 * 
	 * @param data
	 * 		The data in the form of bytes.
	 * 
	 * @return The encrypted bytes, otherwise {@code null} if encryption could not be performed.
	 */
	public static byte[] encrypt(PublicKey key, byte[] data) {		
		try {

			final Cipher cipher = Cipher.getInstance(algorithm);

			cipher.init(Cipher.ENCRYPT_MODE, key);

			return cipher.doFinal(data);

		} catch (Exception ex) {

		}

		return null;

	}

	/**
	 * The method that will decrypt an array of bytes.
	 * 
	 * @param key
	 * 		The {@link PrivateKey} used to decrypt the data.
	 * 
	 * @param encryptedData
	 * 		The encrypted byte array.
	 * 
	 * @return The decrypted data, otherwise {@code null} if decryption could not be performed.
	 */
	public static byte[] decrypt(PrivateKey key, byte[] encryptedData) {		

		try {

			final Cipher cipher = Cipher.getInstance(algorithm);

			cipher.init(Cipher.DECRYPT_MODE, key);

			return cipher.doFinal(encryptedData);

		} catch (Exception ex) {

		}

		return null;

	}
	
	/**
	 * The method that will re-create a {@link PublicKey} from a serialized key.
	 * 
	 * 
	 * @param publicKeyPath
	 * 		The path of the public key file.
	 * 
	 * @throws Exception
	 * 		If there was an issue reading the file.
	 * 
	 * @return The {@link PublicKey} object.
	 */
	public static PublicKey getPublicKey(String publicKeyPath) throws Exception {
		return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Paths.get(publicKeyPath))));
	}
	
	/**
	 * The method that will re-create a {@link PrivateKey} from a serialized key.
	 * 
	 * 
	 * @param privateKeyPath
	 * 		The path of the private key file.
	 * 
	 * @throws Exception
	 * 		If there was an issue reading the file.
	 * 
	 * @return The {@link PrivateKey} object.
	 */
	public static PrivateKey getPrivateKey(String privateKeyPath) throws Exception {
		return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(privateKeyPath))));
	}
		
	/**
	 * The method that will re-create a {@link PublicKey} from a public key byte array.
	 * 
	 * @param encryptedPublicKey
	 * 		The byte array of a public key.
	 * 
	 * @throws Exception
	 * 		If there was an issue reading the byte array.
	 * 
	 * @return The {@link PublicKey} object.
	 */
	public static PublicKey getPublicKey(byte[] encryptedPublicKey) throws Exception {
		return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(encryptedPublicKey));
	}
	
	/**
	 * The method that will re-create a {@link PrivateKey} from a private key byte array.
	 * 
	 * 
	 * @param encryptedPrivateKey
	 * 		The array of bytes of a private key.
	 * 
	 * @throws Exception
	 * 		If there was an issue reading the byte array.
	 * 
	 * @return The {@link PrivateKey} object.
	 */
	public static PrivateKey getPrivateKey(byte[] encryptedPrivateKey) throws Exception {
		return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(encryptedPrivateKey));
	}

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        teksplain = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        enkrip = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        hasil = new javax.swing.JTextField();
        TombolDekrip = new javax.swing.JButton();
        dekrip = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        teksplain.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                teksplainActionPerformed(evt);
            }
        });

        jLabel1.setText("Teks");

        enkrip.setText("Enkrip");
        enkrip.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enkripActionPerformed(evt);
            }
        });

        hasil.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                hasilActionPerformed(evt);
            }
        });

        TombolDekrip.setText("Dekrip");
        TombolDekrip.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TombolDekripActionPerformed(evt);
            }
        });

        dekrip.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dekripActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(17, 17, 17)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(enkrip)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(teksplain, javax.swing.GroupLayout.PREFERRED_SIZE, 320, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(31, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jSeparator1)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(TombolDekrip)
                            .addComponent(hasil, javax.swing.GroupLayout.PREFERRED_SIZE, 350, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(dekrip, javax.swing.GroupLayout.PREFERRED_SIZE, 350, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(0, 0, Short.MAX_VALUE))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(76, 76, 76)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(teksplain, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(enkrip)
                .addGap(18, 18, 18)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(hasil, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(TombolDekrip)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(dekrip, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(61, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void teksplainActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_teksplainActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_teksplainActionPerformed

    private void enkripActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_enkripActionPerformed
        // TODO add your handling code here:
         if(teksplain.getText().equals("")){
            JOptionPane.showMessageDialog(null,"Text Plain dan Key Tidak Boleh Kosong","Perhatian", JOptionPane.ERROR_MESSAGE);
        }else{
             try {
                 generateKey("./public.key", "./private.key");
                 PublicKey publicKey = getPublicKey("./public.key");
                 
                 String data = teksplain.getText();
                 byte[] txt = data.getBytes();
                 
                 byte[] encrypted = encrypt(publicKey, txt);
                 hasil.setText(new String(encrypted));
                 
                 /* DECRYPT */
                 PrivateKey privateKey = getPrivateKey("./private.key");
                 byte[] decrypted = decrypt(privateKey, encrypted);
                 hasildekrip = new String (decrypted);
                 
             } catch (Exception ex) {
                 Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
             }
        }
    }//GEN-LAST:event_enkripActionPerformed

    private void hasilActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_hasilActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_hasilActionPerformed

    private void TombolDekripActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TombolDekripActionPerformed
        try {
            // TODO add your handling code here:
            dekrip.setText(hasildekrip);
            
        } catch (Exception ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_TombolDekripActionPerformed

    private void dekripActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dekripActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dekripActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Main().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton TombolDekrip;
    private javax.swing.JTextField dekrip;
    private javax.swing.JButton enkrip;
    private javax.swing.JTextField hasil;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTextField teksplain;
    // End of variables declaration//GEN-END:variables
}
