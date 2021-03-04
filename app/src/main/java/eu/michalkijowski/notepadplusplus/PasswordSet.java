package eu.michalkijowski.notepadplusplus;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.Base64;
import java.util.concurrent.Executor;

public class PasswordSet extends AppCompatActivity {

    private Executor executor;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_set);

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
        };
        biometricPrompt = new BiometricPrompt(PasswordSet.this, executor, callback);

        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Uwierzytelnianie biometryczne")
                .setSubtitle("Pokaż że to Ty jesteś użytkownikiem tego telefonu")
                .setNegativeButtonText(getString(R.string.whiteflag))
                .build();

        biometricPrompt.authenticate(promptInfo);
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public void checkIdentity(View view)
    {
        String pass1 = ((EditText)findViewById(R.id.setpass1)).getText().toString();
        String pass2 = ((EditText)findViewById(R.id.setpass2)).getText().toString();
        if(pass1.equals(pass2) && !pass1.equals(""))
        {
            try {
                String data = LocalDate.now().toString();
                MainActivity.preferences.edit().putString("date", data).commit();
                String[]dataA = data.split("-");
                pass1 = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest((dataA[0]+pass1+dataA[2]).getBytes()));
                MainActivity.preferences.edit().putString("password", pass1).commit();
                Intent intent = new Intent(this, MainActivity.class);
                startActivity(intent);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        else
        {
            Toast.makeText(getApplicationContext(), R.string.identitypassword, Toast.LENGTH_LONG).show();
        }
    }
}