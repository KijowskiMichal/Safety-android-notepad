package eu.michalkijowski.notepadplusplusv3;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;

public class ChooseMethod extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_choose_method);
    }

    public void passwordLogin(View view)
    {
        Intent intent = new Intent(this, PasswordLogin.class);
        startActivity(intent);
    }

    public void biometricLogin(View view)
    {
        Intent intent = new Intent(this, BiometricLogin.class);
        startActivity(intent);
    }
}