package eu.michalkijowski.notepadplusplusv3;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.concurrent.Executor;

public class PasswordSet extends AppCompatActivity {

    private Executor executor;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

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
                setContentView(R.layout.activity_password_set);
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

    public void savePassword(View view) throws KeyStoreException {
        String pass1 = ((EditText)findViewById(R.id.editTextTextPassword2)).getText().toString();
        String pass2 = ((EditText)findViewById(R.id.editTextTextPassword3)).getText().toString();
        if(pass1.equals(pass2) && !pass1.equals(""))
        {
            VeryVeryImortantClass.fromBiometricGenerateRSA();
            VeryVeryImortantClass.fromPasswordGenerateRSA(pass1);

            VeryVeryImortantClass.hashHashHashHash(pass1);

            VeryVeryImortantClass.saveNotepad("Domyślna notatka");

            Intent intent = new Intent(this, ChooseMethod.class);
            startActivity(intent);
        }
        else
        {
            Toast.makeText(getApplicationContext(), R.string.doubleerror, Toast.LENGTH_SHORT).show();
        }
    }
}