package eu.michalkijowski.notepadplusplus;

import android.content.Intent;
import android.os.Build;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordChange extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_change);
    }


    @RequiresApi(api = Build.VERSION_CODES.O)
    public void setPassword(View view)
    {
        String pass1 = ((EditText)findViewById(R.id.changepass1)).getText().toString();
        String pass2 = ((EditText)findViewById(R.id.changepass2)).getText().toString();
        if(pass1.equals(pass2) && !pass1.equals(""))
        {
            try {

                String text = MainActivity.preferences.getString("text", "");
                String[]dataA = MainActivity.preferences.getString("date", "").split("-");
                String key = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-512").digest((dataA[2]+ MainActivity.getPass()+dataA[1]).getBytes()));
                byte[]keyBytes = key.getBytes();

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKey secretKey = new SecretKeySpec(Arrays.copyOfRange(keyBytes,71,128), 0, 32, "AES");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(Arrays.copyOfRange(keyBytes,7,23)));
                text = Base64.getEncoder().encodeToString(cipher.doFinal(Base64.getDecoder().decode(text)));

                cipher = Cipher.getInstance("DES");
                secretKey = new SecretKeySpec(Arrays.copyOfRange(keyBytes, 43, 51), 0, 8, "DES");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                text = new String(cipher.doFinal(Base64.getDecoder().decode(text)));

                String data = LocalDate.now().toString();
                MainActivity.preferences.edit().putString("date", data).commit();
                dataA = data.split("-");
                String pass3 = pass1;
                pass1 = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest((dataA[0]+pass1+dataA[2]).getBytes()));

                MainActivity.preferences.edit().putString("password", pass1).commit();
                MainActivity.setPass(pass3);

                dataA = MainActivity.preferences.getString("date", "").split("-");
                key = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-512").digest((dataA[2]+MainActivity.getPass()+dataA[1]).getBytes()));
                keyBytes = key.getBytes();

                cipher = Cipher.getInstance("DES");
                secretKey = new SecretKeySpec(Arrays.copyOfRange(keyBytes, 43, 51), 0, 8, "DES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                text = Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes()));

                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                secretKey = new SecretKeySpec(Arrays.copyOfRange(keyBytes,71,128), 0, 32, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(Arrays.copyOfRange(keyBytes,7,23)));
                text = Base64.getEncoder().encodeToString(cipher.doFinal(Base64.getDecoder().decode(text)));

                MainActivity.preferences.edit().putString("text", text).commit();

                ((EditText)findViewById(R.id.changepass1)).setText("");
                ((EditText)findViewById(R.id.changepass2)).setText("");
                Intent intent = new Intent(this, Notepad.class);
                startActivity(intent);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }
        else
        {
            Toast.makeText(getApplicationContext(), R.string.identitypassword, Toast.LENGTH_LONG).show();
        }
    }

    public void goBack(View view)
    {
        Intent intent = new Intent(this, Notepad.class);
        startActivity(intent);
    }
}