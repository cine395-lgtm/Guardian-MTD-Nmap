package com.werebug.anmapwrapper

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.lang.ref.WeakReference

class ImportNmapAssets(private val mainActivityRef: WeakReference<MainActivity>) : Runnable {

  companion object {
    private const val ASSET_VERSION_PREFS_KEY = "last_installed_asset_version"
    // Cambiato in v2 per forzare un aggiornamento immediato al primo avvio
    private const val ASSET_VERSION = "7.99_v2"

    private val NMAP_FILE_ASSETS = arrayOf(
      "nmap-service-probes",
      "nmap-services",
      "nmap-protocols",
      "nmap-rpc",
      "nmap-mac-prefixes",
      "nmap-os-db",
      "nmap-payloads", // Aggiunto per gli script di intrusione
      "nse_main.lua"
    )
    private val NMAP_FOLDER_ASSETS = arrayOf("scripts", "nselib")
  }

  override fun run() {
    // Salvaguardia contro crash se l'Activity viene distrutta
    val activity = mainActivityRef.get() ?: return
    val preferences: SharedPreferences = activity.getPreferences(Context.MODE_PRIVATE)
    val lastImportedVersion = preferences.getString(ASSET_VERSION_PREFS_KEY, "")

    // CONTROLLO ANTI-CORRUZIONE: Verifica fisica se la cartella degli script esiste davvero
    val scriptsDir = File(activity.filesDir, "scripts")
    val isExtractionNeeded = lastImportedVersion != ASSET_VERSION || !scriptsDir.exists() || scriptsDir.listFiles()?.isEmpty() == true

    if (!isExtractionNeeded) {
      Log.i(MainActivity.LOG_TAG, "Assets Nmap già aggiornati e presenti. Bypass estrazione.")
      return
    }

    Log.i(MainActivity.LOG_TAG, "Inizio estrazione dell'arsenale Nmap (Può richiedere alcuni secondi)...")

    for (dataAssetFile in NMAP_FILE_ASSETS) {
      copyAssetFileToInternalStorage(activity, dataAssetFile, dataAssetFile)
    }
    for (assetFolder in NMAP_FOLDER_ASSETS) {
      copyAssetDirToInternalStorage(activity, assetFolder, assetFolder)
    }

    val editor = preferences.edit()
    editor.putString(ASSET_VERSION_PREFS_KEY, ASSET_VERSION)
    editor.apply()

    Log.i(MainActivity.LOG_TAG, "Estrazione Nmap completata con successo!")
  }

  private fun copyAssetFileToInternalStorage(activity: MainActivity, assetPath: String, targetPath: String) {
    val targetFile = File(activity.filesDir, targetPath)

    // Assicura che le sottocartelle esistano prima di copiare il file
    targetFile.parentFile?.mkdirs()

    var inputStream: InputStream? = null
    var outputStream: OutputStream? = null
    try {
      inputStream = activity.assets.open(assetPath)
      outputStream = FileOutputStream(targetFile)
      val buffer = ByteArray(4096) // Buffer a 4K per estrazione fulminea
      var length: Int
      while (inputStream.read(buffer).also { length = it } > 0) {
        outputStream.write(buffer, 0, length)
      }
    } catch (e: IOException) {
      Log.e(MainActivity.LOG_TAG, "Errore durante l'importazione di $assetPath: ${e.message}")
    } finally {
      try {
        inputStream?.close()
        outputStream?.flush()
        outputStream?.close()
      } catch (e: IOException) {
        // Ignora chiusura fallita
      }
    }
  }

  private fun copyAssetDirToInternalStorage(activity: MainActivity, assetDir: String, targetDir: String) {
    val assets = try {
      activity.assets.list(assetDir)
    } catch (e: IOException) {
      null
    } ?: return

    val targetDirectory = File(activity.filesDir, targetDir)
    if (!targetDirectory.exists()) {
      targetDirectory.mkdirs()
    }

    for (asset in assets) {
      val assetPath = if (assetDir.isEmpty()) asset else "$assetDir/$asset"
      val targetPath = "$targetDir/$asset"

      // Check sicuro per capire se l'elemento è una cartella o un file
      val isDirectory = try {
        val subAssets = activity.assets.list(assetPath)
        subAssets != null && subAssets.isNotEmpty()
      } catch (e: IOException) {
        false
      }

      if (isDirectory) {
        copyAssetDirToInternalStorage(activity, assetPath, targetPath)
      } else {
        copyAssetFileToInternalStorage(activity, assetPath, targetPath)
      }
    }
  }
}