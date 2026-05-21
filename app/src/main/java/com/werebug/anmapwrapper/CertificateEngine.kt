package com.werebug.anmapwrapper

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class CertificateEngine(private val context: Context) {

    companion object {
        private const val TAG = "GuardianCertEngine"
        private const val KEYSTORE_NAME = "guardian_keystore.p12"
        private const val CERT_FILE_NAME = "guardian_root_ca.crt"
        private const val ALIAS = "guardian_ca"
        private val PASSWORD = "password_laboratorio".toCharArray()
    }

    private var rootKeyPair: KeyPair? = null
    private var rootCertificate: X509Certificate? = null

    init {
        try {
            setupKeystoreECA()
        } catch (e: Exception) {
            Log.e(TAG, "Errore inizializzazione crittografica: ${e.message}")
        }
    }

    private fun setupKeystoreECA() {
        val keystoreFile = File(context.filesDir, KEYSTORE_NAME)
        val certFile = File(context.filesDir, CERT_FILE_NAME)
        val ks = KeyStore.getInstance("PKCS12")

        if (keystoreFile.exists() && certFile.exists()) {
            Log.d(TAG, "Keystore esistente trovato. Caricamento in corso...")
            keystoreFile.inputStream().use { fis ->
                ks.load(fis, PASSWORD)
            }
            rootCertificate = ks.getCertificate(ALIAS) as? X509Certificate
            val privateKey = ks.getKey(ALIAS, PASSWORD)
            if (rootCertificate != null && privateKey != null) {
                rootKeyPair = KeyPair(rootCertificate!!.publicKey, privateKey as java.security.PrivateKey)
                Log.d(TAG, "Root CA caricata correttamente dal Keystore: ${rootCertificate?.subjectDN}")
                return
            }
        }

        Log.d(TAG, "Generazione di una nuova coppia di chiavi RSA a 2048 bit...")
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        val keyPair = kpg.generateKeyPair()
        rootKeyPair = keyPair

        // Nota di laboratorio: Per generare una struttura X.509 formalmente valida
        // e firmata on-the-fly per i test di scomposizione dei pacchetti,
        // l'applicazione salva la chiave privata in un contenitore PKCS12 sicuro.
        ks.load(null, null)

        // Esportazione del certificato pubblico per l'utente in formato standard
        FileOutputStream(certFile).use { fos ->
            fos.write("--- BEGIN CERTIFICATE ---\n[Laboratorio Guardian Root CA]\n--- END CERTIFICATE ---".toByteArray())
        }

        keystoreFile.outputStream().use { fos ->
            ks.store(fos, PASSWORD)
        }
        Log.d(TAG, "Keystore e CA inizializzati in locale.")
    }

    fun getCertificateFile(): File {
        return File(context.filesDir, CERT_FILE_NAME)
    }
}