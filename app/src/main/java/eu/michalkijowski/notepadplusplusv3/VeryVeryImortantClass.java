package eu.michalkijowski.notepadplusplusv3;

import android.annotation.SuppressLint;
import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import static eu.michalkijowski.notepadplusplusv3.MainActivity.preferences;

public class VeryVeryImortantClass {
    private static final String KEY_ALIAS = "passnotepadplusplusv2";

    private static Executor executor;
    private static BiometricPrompt biometricPrompt;
    private static BiometricPrompt.PromptInfo promptInfo;

    public static PublicKey publicKey = null;
    public static PrivateKey privateKey = null;
    public static SecretKey passwordSecret = null;

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALIAS = "test-key";
    private static final String TRANSFORMATION = "AES/CBC/PKCS7Padding";

    public static PublicKey fromPasswordRSAGetPublic()
    {
        try {
            byte[] byteKey = Base64.getDecoder().decode(preferences.getString("biometricPublic", null));
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(X509publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }
    public static PrivateKey fromPasswordRSAGetPrivate(String password)
    {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), Base64.getDecoder().decode(preferences.getString("saltPrivate", null)), 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            passwordSecret = factory.generateSecret(spec);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKey secretKey = new SecretKeySpec(passwordSecret.getEncoded(), 0, 32, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(Base64.getDecoder().decode(preferences.getString("ivPrivate", null))));

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(cipher.doFinal(Base64.getDecoder().decode(preferences.getString("passwordPrivate", null))));
            privateKey = kf.generatePrivate(keySpecPKCS8);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return privateKey;
    }
    public static PublicKey fromBiometricRSAGetPublic()
    {
        try {
            byte[] byteKey = Base64.getDecoder().decode(preferences.getString("passwordPublic", null));
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(X509publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }
    public static PrivateKey fromBiometricRSAGetPrivate()
    {
        try
        {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            return (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return null;
    }
    public static void fromPasswordGenerateRSA(String password)
    {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048, new SecureRandom());
            KeyPair pair = generator.generateKeyPair();

            SecureRandom srandom = new SecureRandom();
            byte[] salt = new byte[32];
            srandom.nextBytes(salt);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            passwordSecret = factory.generateSecret(spec);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKey secretKey = new SecretKeySpec(passwordSecret.getEncoded(), 0, 32, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            preferences.edit().putString("passwordPublic", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())).commit();
            preferences.edit().putString("passwordPrivate", Base64.getEncoder().encodeToString(cipher.doFinal(pair.getPrivate().getEncoded()))).commit();
            preferences.edit().putString("ivPrivate", Base64.getEncoder().encodeToString(cipher.getIV())).commit();
            preferences.edit().putString("saltPrivate", Base64.getEncoder().encodeToString(salt)).commit();

            byte[] byteKey = Base64.getDecoder().decode(preferences.getString("biometricPublic", null));
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(X509publicKey);
            privateKey = pair.getPrivate();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
    @SuppressLint("ApplySharedPref")
    public static void fromBiometricGenerateRSA()
    {
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyGenerator.initialize(new KeyGenParameterSpec.Builder(KEY_ALIAS,KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setKeySize(2048)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .build());
            keyGenerator.generateKeyPair();

            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            PublicKey key = keyStore.getCertificate(KEY_ALIAS).getPublicKey();
            PublicKey unrestrictedPublicKey = KeyFactory.getInstance(key.getAlgorithm()).generatePublic(new X509EncodedKeySpec(key.getEncoded()));

            preferences.edit().putString("biometricPublic", Base64.getEncoder().encodeToString(unrestrictedPublicKey.getEncoded())).commit();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException | KeyStoreException | CertificateException | IOException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public static void hashHashHashHash(String password)
    {
        try
        {
            SecureRandom srandom = new SecureRandom();
            byte[] salt = new byte[16];
            srandom.nextBytes(salt);
            String saltinio = Base64.getEncoder().encodeToString(salt);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((password+saltinio).getBytes());
            preferences.edit().putString("saltinio", saltinio).commit();
            preferences.edit().putString("password", Base64.getEncoder().encodeToString(hash)).commit();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static boolean hashHashHashHashCheckup(String password)
    {
        try
        {
            String saltinio = preferences.getString("saltinio", null);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((password+saltinio).getBytes());
            if (Base64.getEncoder().encodeToString(hash).equals(preferences.getString("password", null)))
            {
                return true;
            }
            else return false;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static SecretKey generateAndSaveNewKey()
    {
        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();
            Cipher cipher;
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, fromPasswordRSAGetPublic(), new OAEPParameterSpec("SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA1,
                    PSource.PSpecified.DEFAULT));
            preferences.edit().putString("keyPassword", Base64.getEncoder().encodeToString(cipher.doFinal(secretKey.getEncoded()))).commit();
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, fromBiometricRSAGetPublic());
            preferences.edit().putString("keyBiometric", Base64.getEncoder().encodeToString(cipher.doFinal(secretKey.getEncoded()))).commit();
            return secretKey;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static SecretKey getKey()
    {
        try
        {
            if (MainActivity.password.equals(""))
            {
                Cipher cipher;
                cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                cipher.init(Cipher.DECRYPT_MODE, fromBiometricRSAGetPrivate(), new OAEPParameterSpec("SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA1,
                        PSource.PSpecified.DEFAULT));
                System.out.println("abcd: "+(Base64.getDecoder().decode(MainActivity.getPreferences().getString("keyPassword", null))).length);
                return new SecretKeySpec(cipher.doFinal(Base64.getDecoder().decode(MainActivity.getPreferences().getString("keyPassword", null))), "RSA");
            }
            else
            {
                Cipher cipher;
                cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                cipher.init(Cipher.DECRYPT_MODE, fromPasswordRSAGetPrivate(MainActivity.password));
                SecretKey secretKey = new SecretKeySpec(cipher.doFinal(Base64.getDecoder().decode(MainActivity.getPreferences().getString("keyBiometric", null))), "RSA");
                return  secretKey;
            }
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return (SecretKey)null;
    }

    public static void saveNotepad(String content)
    {
        try
        {
            Cipher cipher;
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, VeryVeryImortantClass.generateAndSaveNewKey());
            preferences.edit().putString("content", Base64.getEncoder().encodeToString(cipher.doFinal(content.getBytes()))).commit();
            preferences.edit().putString("keyIV", Base64.getEncoder().encodeToString(cipher.getIV())).commit();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public static  String readNotepad()
    {
        try {
            Cipher cipher;
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, VeryVeryImortantClass.getKey(), new IvParameterSpec(Base64.getDecoder().decode(MainActivity.getPreferences().getString("keyIV", null))));
            return new String(cipher.doFinal(Base64.getDecoder().decode(MainActivity.getPreferences().getString("content", ""))));
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }
}
