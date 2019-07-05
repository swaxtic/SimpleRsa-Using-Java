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
         String hasildekripp;
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

        jPanel1 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        teksplain = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        Nama = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        no_akun = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        enkrip = new javax.swing.JButton();
        hasil = new javax.swing.JTextField();
        jSeparator2 = new javax.swing.JSeparator();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        nama_public = new javax.swing.JTextField();
        no_akun_public = new javax.swing.JTextField();
        jLabel11 = new javax.swing.JLabel();
        jSeparator1 = new javax.swing.JSeparator();
        Dekrip = new javax.swing.JButton();
        hasil_dekrip = new javax.swing.JTextField();
        jLabel12 = new javax.swing.JLabel();
        jLabel13 = new javax.swing.JLabel();
        jLabel14 = new javax.swing.JLabel();
        jLabel15 = new javax.swing.JLabel();
        nama_public_dekrip = new javax.swing.JTextField();
        no_akun_public1 = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel1.setBackground(new java.awt.Color(213, 211, 213));

        jLabel2.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel2.setText("ACCOUNT INFORMATION");

        teksplain.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                teksplainActionPerformed(evt);
            }
        });

        jLabel1.setText("NAMA");

        Nama.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NamaActionPerformed(evt);
            }
        });

        jLabel4.setText("NO. AKUN");

        jLabel3.setText("SALDO");

        jLabel5.setText("Rp.");

        enkrip.setText("SAVE");
        enkrip.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enkripActionPerformed(evt);
            }
        });

        hasil.setEditable(false);
        hasil.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                hasilActionPerformed(evt);
            }
        });

        jLabel6.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel6.setText("ACCOUNT INFORMATION (PUBLIC VIEW)");

        jLabel7.setText("NAMA");

        jLabel8.setText("NO. AKUN");

        jLabel9.setText("SALDO");

        jLabel10.setText("Rp.");

        nama_public.setEditable(false);

        no_akun_public.setEditable(false);

        jLabel11.setForeground(new java.awt.Color(84, 84, 84));
        jLabel11.setText("Swaxtic (dip) A11.2016.09807");

        Dekrip.setText("DECRYPT");
        Dekrip.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DekripActionPerformed(evt);
            }
        });

        hasil_dekrip.setEditable(false);
        hasil_dekrip.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                hasil_dekripActionPerformed(evt);
            }
        });

        jLabel12.setText("NAMA");

        jLabel13.setText("NO. AKUN");

        jLabel14.setText("SALDO");

        jLabel15.setText("Rp.");

        nama_public_dekrip.setEditable(false);
        nama_public_dekrip.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nama_public_dekripActionPerformed(evt);
            }
        });

        no_akun_public1.setEditable(false);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jSeparator1)
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel2)
                                .addGap(186, 186, 186))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel6)
                                .addGap(90, 90, 90))))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel9)
                            .addComponent(jLabel7)
                            .addComponent(jLabel8))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel10)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(hasil, javax.swing.GroupLayout.PREFERRED_SIZE, 359, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(nama_public)
                            .addComponent(no_akun_public, javax.swing.GroupLayout.PREFERRED_SIZE, 386, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(64, 64, 64))))
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(262, 262, 262)
                .addComponent(Dekrip)
                .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jSeparator2)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel1)
                                    .addComponent(jLabel4)
                                    .addComponent(jLabel3))
                                .addGap(68, 68, 68)
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                        .addComponent(jLabel5)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(teksplain, javax.swing.GroupLayout.PREFERRED_SIZE, 214, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addComponent(enkrip)
                                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                            .addComponent(Nama)
                                            .addComponent(no_akun, javax.swing.GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE))))
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel14)
                                    .addComponent(jLabel12)
                                    .addComponent(jLabel13))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 99, Short.MAX_VALUE)
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                        .addComponent(jLabel15)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(hasil_dekrip, javax.swing.GroupLayout.PREFERRED_SIZE, 359, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addComponent(nama_public_dekrip)
                                    .addComponent(no_akun_public1, javax.swing.GroupLayout.PREFERRED_SIZE, 386, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(57, 57, 57))))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(jLabel11)))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jLabel2)
                .addGap(31, 31, 31)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(Nama, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(no_akun, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(9, 9, 9)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(teksplain, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3)
                    .addComponent(jLabel5))
                .addGap(18, 18, 18)
                .addComponent(enkrip)
                .addGap(11, 11, 11)
                .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel6)
                .addGap(12, 12, 12)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel7)
                    .addComponent(nama_public, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(6, 6, 6)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel8)
                    .addComponent(no_akun_public, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel9)
                    .addComponent(hasil, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel10))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(Dekrip)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel12)
                        .addGap(12, 12, 12)
                        .addComponent(jLabel13)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel14)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 14, Short.MAX_VALUE)
                        .addComponent(nama_public_dekrip, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(6, 6, 6)
                        .addComponent(no_akun_public1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(hasil_dekrip, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel15))
                        .addGap(18, 18, 18)))
                .addComponent(jLabel11))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
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
                 
                 /** VIGENEERE */
                vigen vgn = new vigen();
                String key = no_akun.getText().toUpperCase();
                String enkript = vgn.encrypt(Nama.getText(), key);
                nama_public.setText(enkript);
                 
                 /* DECRYPT */
                 PrivateKey privateKey = getPrivateKey("./private.key");
                 byte[] decrypted = decrypt(privateKey, encrypted);
                 hasildekripp = new String (decrypted);
                 
                 
                 no_akun_public.setText(key);
                 
             } catch (Exception ex) {
                 Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
             }
        }
    }//GEN-LAST:event_enkripActionPerformed

    private void hasilActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_hasilActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_hasilActionPerformed

    private void NamaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NamaActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_NamaActionPerformed

    private void hasil_dekripActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_hasil_dekripActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_hasil_dekripActionPerformed

    private void nama_public_dekripActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nama_public_dekripActionPerformed
        // TODO add your handling code here:
        
    }//GEN-LAST:event_nama_public_dekripActionPerformed

    private void DekripActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DekripActionPerformed
        if(nama_public.getText().equals("")){
           JOptionPane.showMessageDialog(null,"Tidak Dapat Menemukan Text Enskripsi","Perhatian", JOptionPane.ERROR_MESSAGE);
        }
        vigen vgn = new vigen();
        String key = no_akun.getText().toUpperCase();
        String enkript = Nama.getText();
        
        nama_public_dekrip.setText(vgn.decrypt(enkript, key));
        no_akun_public1.setText(key);
        hasil_dekrip.setText(hasildekripp);
    }//GEN-LAST:event_DekripActionPerformed

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
    private javax.swing.JButton Dekrip;
    private javax.swing.JTextField Nama;
    private javax.swing.JButton enkrip;
    private javax.swing.JTextField hasil;
    private javax.swing.JTextField hasil_dekrip;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JTextField nama_public;
    private javax.swing.JTextField nama_public_dekrip;
    private javax.swing.JTextField no_akun;
    private javax.swing.JTextField no_akun_public;
    private javax.swing.JTextField no_akun_public1;
    private javax.swing.JTextField teksplain;
    // End of variables declaration//GEN-END:variables
}
