package com.hridoy.securefile

import android.app.Activity
import android.os.Bundle
import android.content.Intent
import android.net.Uri
import android.widget.*
import android.graphics.Color
import android.graphics.Typeface
import androidx.core.content.FileProvider
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import java.io.File
import java.io.FileOutputStream

class MainActivity : Activity() {

    private lateinit var password: EditText
    private lateinit var confirm: EditText
    private lateinit var fileInfo: TextView
    private var selectedUri: Uri? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 35, 28, 25)
            setBackgroundColor(Color.WHITE)
        }

        val title = TextView(this).apply {
            text = "Hridoy Secure File"
            textSize = 26f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.rgb(25, 70, 130))
        }
        layout.addView(title)

        fileInfo = TextView(this).apply {
            text = "No file selected"
            textSize = 15f
            setPadding(0, 20, 0, 10)
        }
        layout.addView(fileInfo)

        val choose = Button(this).apply {
            text = "Select File"
        }
        layout.addView(choose)

        password = EditText(this).apply {
            hint = "Enter Password (minimum 8 characters)"
            inputType = 129
        }
        layout.addView(password)

        confirm = EditText(this).apply {
            hint = "Confirm Password"
            inputType = 129
        }
        layout.addView(confirm)

        val encrypt = Button(this).apply {
            text = "Encrypt & Share"
        }
        layout.addView(encrypt)

        val note = TextView(this).apply {
            text = "Share your password separately."
            setPadding(0, 20, 0, 0)
        }
        layout.addView(note)

        setContentView(layout)

        choose.setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                type = "*/*"
                addCategory(Intent.CATEGORY_OPENABLE)
            }
            startActivityForResult(intent, 100)
        }

        encrypt.setOnClickListener {
            encryptAndShare()
        }
    }

    @Deprecated("Deprecated in Android API")
    override fun onActivityResult(
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == 100 && resultCode == RESULT_OK) {
            selectedUri = data?.data
            fileInfo.text = "Selected: ${selectedUri?.lastPathSegment ?: "File"}"
        }
    }

    private fun encryptAndShare() {
        val uri = selectedUri
        val pass = password.text.toString()
        val confirmPass = confirm.text.toString()

        if (uri == null) {
            Toast.makeText(this, "Select a file first", Toast.LENGTH_SHORT).show()
            return
        }

        if (pass.length < 8) {
            password.error = "Minimum 8 characters"
            return
        }

        if (pass != confirmPass) {
            confirm.error = "Passwords do not match"
            return
        }

        try {
            val original = contentResolver.openInputStream(uri)?.use {
                it.readBytes()
            } ?: throw Exception("Cannot read selected file")

            val random = SecureRandom()
            val salt = ByteArray(16).also { random.nextBytes(it) }
            val iv = ByteArray(12).also { random.nextBytes(it) }

            val spec = PBEKeySpec(
                pass.toCharArray(), salt, 310000, 256
            )

            val keyBytes = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).encoded

            spec.clearPassword()

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(keyBytes, "AES"),
                GCMParameterSpec(128, iv)
            )

            val encrypted = cipher.doFinal(original)

            val output = File(
                cacheDir,
                "Hridoy_${System.currentTimeMillis()}.hsf"
            )

            FileOutputStream(output).use {
                it.write("HSF1".toByteArray(Charsets.US_ASCII))
                it.write(salt)
                it.write(iv)
                it.write(encrypted)
            }

            val shareUri = FileProvider.getUriForFile(
                this,
                "$packageName.provider",
                output
            )

            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_STREAM, shareUri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

            startActivity(
                Intent.createChooser(shareIntent, "Share encrypted file")
            )

        } catch (e: Exception) {
            Toast.makeText(
                this,
                "Error: ${e.message}",
                Toast.LENGTH_LONG
            ).show()
        }
    }
}
