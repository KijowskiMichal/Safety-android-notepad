package eu.michalkijowski.notepadplusplusv3;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

import java.util.concurrent.Executor;

public class BiometricLogin extends AppCompatActivity {

    private Executor executor;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_biometric_login);

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
                MainActivity.login = true;
                Intent intent = new Intent(getApplicationContext(), MainActivity.class);
                startActivity(intent);
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
}