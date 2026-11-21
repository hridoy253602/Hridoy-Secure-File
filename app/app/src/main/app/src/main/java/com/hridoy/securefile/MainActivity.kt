package com.hridoy.securefile

import android.app.Activity
import android.os.Bundle
import android.content.Intent
import android.net.Uri
import android.widget.*
import android.view.ViewGroup
import android.graphics.Typeface
import android.graphics.Color
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
    private var selectedUri: Uri? = null
    private var selectedName = "file"

    private val pickFile = 100

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this)
        layout.orientation = LinearLayout.VERTICAL
        layout.setPadding(28, 35, 28, 25)
        layout.setBackgroundColor(Color.WHITE)

        val title = TextView(this)
        title.text = "Hridoy Secure File"
        title.textSize = 26f
        title.setTypeface(null, Typeface.BOLD)
        title.setTextColor(Color.rgb(25, 70, 130))
        layout.addView(title)

        val info = TextView(this)
        info.text = "Encrypt your files before sharing"
        info.textSize = 15f
        info.setPadding(0, 12, 0, 25)
        layout.addView(info)

        val choose = Button(this)
        choose.text = "Select File"
        layout.addView(choose)

        password = EditText(this)
        password.hint = "Enter Password"
        password.inputType = 129
        layout.addView(password)

        confirm = EditText(this)
        confirm.hint = "Confirm Password"
        confirm.inputType = 129
        layout.addView(confirm)

        val encrypt = Button(this)
        encrypt.text = "Encrypt & Share"
        layout.addView(encrypt)

        val note = TextView(this)
        note.text = "Keep your password safe. Share it separately."
        note.setPadding(0, 20, 0, 0)
        layout.addView(note)

        setContentView(layout)

        choose.setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            intent.type = "*/*"
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            startActivityForResult(intent, pickFile)
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

        if (requestCode == pickFile && resultCode == RESULT_OK) {
            selectedUri = data?.data
            selectedName = selectedUri?.lastPathSegment ?: "file"
            Toast.makeText(this, "File selected", Toast.LENGTH_SHORT).show()
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
            password.error = "Use at least 8 characters"
            return
        }

        if (pass != confirmPass) {
            confirm.error = "Passwords do not match"
            return
        }

        try {
            val input = contentResolver.openInputStream(uri)
                ?: throw Exception("Cannot read file")
            val original = input.use { it.readBytes() }

            val random = SecureRandom()
            val salt = ByteArray(16).also { random.nextBytes(it) }
            val iv = ByteArray(12).also { random.nextBytes(it) }

            val spec = PBEKeySpec(pass.toCharArray(), salt, 310000, 256)
            val keyBytes = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).encoded

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val key = SecretKeySpec(keyBytes, "AES")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))

            val encrypted = cipher.doFinal(original)

            val output = File(cacheDir, "Hridoy_${System.currentTimeMillis()}.hsf")
            FileOutputStream(output).use {
                it.write("HSF1".toByteArray(Charsets.US_ASCII))
                it.write(salt)
                it.write(iv)
                it.write(encrypted)
            }

            val shareIntent = Intent(Intent.ACTION_SEND)
            shareIntent.type = "application/octet-stream"
            shareIntent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(output))
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)

            startActivity(Intent.createChooser(shareIntent, "Share encrypted file"))

        } catch (e: Exception) {
            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
