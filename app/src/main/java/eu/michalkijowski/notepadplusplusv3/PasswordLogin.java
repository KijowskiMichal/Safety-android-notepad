package eu.michalkijowski.notepadplusplusv3;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

public class PasswordLogin extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_login);
    }

    public void login(View view)
    {
        String pass = ((EditText)findViewById(R.id.editTextTextPassword4)).getText().toString();
        if(!pass.equals(""))
        {
            if (VeryVeryImortantClass.hashHashHashHashCheckup(pass))
            {
                MainActivity.login = true;
                MainActivity.password = pass;
                Intent intent = new Intent(this, MainActivity.class);
                startActivity(intent);
            }
            else
            {
                Toast.makeText(getApplicationContext(), R.string.autherr, Toast.LENGTH_SHORT).show();
            }
        }
        else
        {
            Toast.makeText(getApplicationContext(), R.string.autherr, Toast.LENGTH_SHORT).show();
        }
    }
}