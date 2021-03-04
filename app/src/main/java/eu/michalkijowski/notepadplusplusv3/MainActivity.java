package eu.michalkijowski.notepadplusplusv3;

import android.content.Intent;
import android.content.SharedPreferences;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import java.util.Base64;

public class MainActivity extends AppCompatActivity {

    public static SharedPreferences preferences;
    public static boolean login = false;
    public static String password = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        preferences = getSharedPreferences("Preferences", AppCompatActivity.MODE_PRIVATE);

        if (preferences.getString("passwordPublic", null)==null)
        {
            Intent intent = new Intent(this, PasswordSet.class);
            startActivity(intent);
        }
        else if (!login)
        {
            Intent intent = new Intent(this, ChooseMethod.class);
            startActivity(intent);
        }
        else
        {
            setContentView(R.layout.activity_main);

            ((EditText) findViewById(R.id.editTextTextMultiLine)).setText(VeryVeryImortantClass.readNotepad());
        }
    }

    public static SharedPreferences getPreferences() {
        return preferences;
    }

    public static void setPreferences(SharedPreferences preferences) {
        MainActivity.preferences = preferences;
    }

    public void save(View view)
    {
        VeryVeryImortantClass.saveNotepad(((EditText) findViewById(R.id.editTextTextMultiLine)).getText().toString());
        Toast.makeText(getApplicationContext(), R.string.saved, Toast.LENGTH_SHORT).show();
    }

    public void goToPasswordChange(View view)
    {
        Intent intent = new Intent(this, PaswordChange.class);
        startActivity(intent);
    }
}