package eu.michalkijowski.notepadplusplusv2;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainActivity extends AppCompatActivity {

    private static final String KEY_ALIAS = "passnotepadplusplusv2";

    private Executor executor;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ALIAS = "test-key";
    private static final String TRANSFORMATION = "AES/CBC/PKCS7Padding";

    public SharedPreferences preferences;
    public boolean flag = false;
    public View view;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        preferences = getSharedPreferences("Preferences", AppCompatActivity.MODE_PRIVATE);

        update();

        executor = ContextCompat.getMainExecutor(this);
        BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode,
                                              @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(getApplicationContext(), R.string.autherr, Toast.LENGTH_SHORT).show();
                finishAndRemoveTask();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                finishAndRemoveTask();
            }

            @Override
            public void onAuthenticationSucceeded (BiometricPrompt.AuthenticationResult result) {
                if (!flag) update();
                else save(view);
                flag = false;
            }
        };
        biometricPrompt = new BiometricPrompt(this, executor, callback);

        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Uwierzytelnianie biometryczne")
                .setSubtitle("Pokaż że to Ty jesteś użytkownikiem tego telefonu")
                .setNegativeButtonText(getString(R.string.whiteflag))
                .build();

        biometricPrompt.authenticate(promptInfo);
    }


    public void save(View view) {
        String text = ((EditText)findViewById(R.id.editTextTextMultiLine)).getText().toString();
        try {
            Cipher cipher;
            SecretKey secretKey;
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            secretKey = ((KeyStore.SecretKeyEntry) keyStore.getEntry(ALIAS, null)).getSecretKey();

            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            preferences.edit().putString("iv", Base64.getEncoder().encodeToString(cipher.getIV())).commit();
            preferences.edit().putString("text", Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes()))).commit();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            flag = true;
            this.view = view;
            biometricPrompt.authenticate(promptInfo);
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public void update()
    {
        Cipher cipher;
        SecretKey secretKey;
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            if (!keyStore.containsAlias(ALIAS))
            {
                try {
                    KeyGenParameterSpec aesSpec = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .setIsStrongBoxBacked(true)
                            .setKeySize(128)
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(5)
                            .build();

                    KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
                    keyGenerator.init(aesSpec);
                    keyGenerator.generateKey();
                } catch (InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchProviderException e) {
                    e.printStackTrace();
                }
            }
            else {
                secretKey = ((KeyStore.SecretKeyEntry) keyStore.getEntry(ALIAS, null)).getSecretKey();
                IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(preferences.getString("iv", "")));
                cipher = Cipher.getInstance(TRANSFORMATION);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

                ((EditText) findViewById(R.id.editTextTextMultiLine)).setText(new String(cipher.doFinal(Base64.getDecoder().decode(preferences.getString("text", "")))));
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }
}