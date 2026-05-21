package com.werebug.anmapwrapper

import android.os.Handler
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import java.io.BufferedReader
import java.io.InputStreamReader
import java.lang.ref.WeakReference
import com.werebug.anmapwrapper.R // <--- FORZA L'IMPORT DELLE RISORSE DEL TUO PROGETTO

class NmapScan internal constructor(
  private val mainActivityRef: WeakReference<MainActivity>,
  private val command: List<String>,
  private val mainThreadHandler: Handler,
  private val libDir: String
) : Runnable {
  private var stopped = false
  private var process: Process? = null

  override fun run() {
    val processBuilder = ProcessBuilder(command)

    // Impostazione ambiente per le librerie native
    val env = processBuilder.environment()
    env["LD_LIBRARY_PATH"] = libDir
    env["PATH"] = "$libDir:/system/bin:/system/xbin"
    processBuilder.redirectErrorStream(true)

    try {
      process = processBuilder.start()
      val reader = BufferedReader(InputStreamReader(process?.inputStream))
      var line: String?

      // UNICO CICLO DI LETTURA: Legge l'output di Nmap riga per riga
      // UNICO CICLO DI LETTURA: Legge l'output di Nmap riga per riga
      while (reader.readLine().also { line = it } != null) {
        if (stopped) break
        val currentLine = line ?: continue

        // Forza il cast sicuro sull'activity per sbloccare la chiamata della funzione
        mainThreadHandler.post {
          val activity = mainActivityRef.get() as? MainActivity
          activity?.elaboraEVisualizzaRigaNmap(currentLine)
        }
      }

      // Attesa chiusura processo
      val exitCode = process?.waitFor() ?: -1

      // Notifica fine scansione sulla UI
      mainThreadHandler.post {
        val activity = mainActivityRef.get()
        if (activity != null) {
          // Modifichiamo la variabile di stato dentro la MainActivity
          activity.isScanning = false

          // Troviamo i componenti passando esplicitamente dalla activity di riferimento
          activity.findViewById<Button>(R.id.btnScan)?.text = "AVVIA SCANSIONE"

          val message = if (exitCode != 0) {
            "\n⚠️ Terminato con errore (Codice: $exitCode)\n"
          } else {
            "\n📊 Analisi completata.\n"
          }
          activity.findViewById<TextView>(R.id.tvNmapResult)?.append(message)
        }
      }

    } catch (e: Exception) {
      Log.e("NmapScan", "Errore scansione: ${e.message}")
      mainThreadHandler.post {
        val activity = mainActivityRef.get()
        if (activity != null) {
          activity.isScanning = false
          activity.findViewById<Button>(R.id.btnScan)?.text = "AVVIA SCANSIONE"
          Toast.makeText(activity, "Errore: ${e.message}", Toast.LENGTH_LONG).show()
        }
      }
    }
  }

  fun stopScan() {
    stopped = true
    process?.destroy()
  }
}