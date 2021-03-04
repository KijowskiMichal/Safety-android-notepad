package eu.michalkijowski.notepadplusplusv3;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

public class PaswordChange extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pasword_change);
    }

    public void passwordchange(View view)
    {
        String pass1 = ((EditText)findViewById(R.id.editTextTextPassword5)).getText().toString();
        String pass2 = ((EditText)findViewById(R.id.editTextTextPassword6)).getText().toString();
        if(pass1.equals(pass2) && !pass1.equals(""))
        {
            String note = VeryVeryImortantClass.readNotepad();

            VeryVeryImortantClass.fromPasswordGenerateRSA(pass1);

            VeryVeryImortantClass.hashHashHashHash(pass1);

            VeryVeryImortantClass.saveNotepad(note);

            Intent intent = new Intent(this, MainActivity.class);
            startActivity(intent);
        }
        else
        {
            Toast.makeText(getApplicationContext(), R.string.doubleerror, Toast.LENGTH_SHORT).show();
        }
    }
}