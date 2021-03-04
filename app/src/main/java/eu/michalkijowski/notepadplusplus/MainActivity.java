package eu.michalkijowski.notepadplusplus;

import android.content.Intent;
import android.content.SharedPreferences;

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
import java.util.Base64;
import java.util.concurrent.Executor;


public class MainActivity extends AppCompatActivity {

    private Executor executor;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;

    public static SharedPreferences preferences;

    public static String getPass() {
        return pass;
    }

    public static void setPass(String pass) {
        MainActivity.pass = pass;
    }

    public static String pass = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        MainActivity.preferences = getSharedPreferences("Preferences", AppCompatActivity.MODE_PRIVATE);
        if (!MainActivity.preferences.contains("password"))
        {
            Intent intent = new Intent(this, PasswordSet.class);
            startActivity(intent);
        }
        else {
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
            biometricPrompt = new BiometricPrompt(MainActivity.this, executor, callback);

            promptInfo = new BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Uwierzytelnianie biometryczne")
                    .setSubtitle("Pokaż że to Ty jesteś użytkownikiem tego telefonu")
                    .setNegativeButtonText(getString(R.string.whiteflag))
                    .build();

            biometricPrompt.authenticate(promptInfo);
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public void goToTheNotepad(View view) {
        String pass = ((EditText)findViewById(R.id.editTextTextPassword)).getText().toString();
        String[]dataA = MainActivity.preferences.getString("date", "").split("-");
        try {
            MainActivity.setPass(pass);
            pass = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest((dataA[0]+pass+dataA[2]).getBytes()));
            if (pass.equals(MainActivity.preferences.getString("password", ""))) {
                Intent intent = new Intent(this, Notepad.class);
                startActivity(intent);
            }
            else
            {
                Toast.makeText(getApplicationContext(), R.string.passwordNotCorrect, Toast.LENGTH_LONG).show();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void goToThePasswordChange(View view) {
        Intent intent = new Intent(this, PasswordChange.class);
        startActivity(intent);
    }
}