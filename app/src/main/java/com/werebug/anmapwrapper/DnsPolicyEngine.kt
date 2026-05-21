package com.werebug.anmapwrapper

import android.content.Context
import android.util.Log
import java.io.File
import java.util.Locale

object DnsPolicyEngine {

    private const val TAG = "DnsPolicyEngine"
    private const val DENYLIST_FILENAME = "guardian_denylist.txt"

    @Volatile
    private var denylist: Set<String> = emptySet()

    fun getActiveDomains(): Set<String> = denylist

    fun shouldBlock(domain: String?): Boolean {
        if (domain.isNullOrBlank()) return false
        val normalized = domain.trim().trimEnd('.').lowercase(Locale.ROOT)
        return denylist.any { blocked ->
            normalized == blocked || normalized.endsWith(".$blocked")
        }
    }

    // =========================================================================
    // MODIFICA: Funzione di svuotamento RAM (Risolve l'errore rosso nel Servizio)
    // =========================================================================
    fun clearDenylist() {
        denylist = emptySet()
        Log.d(TAG, "Memoria volatile della Denylist azzerata.")
    }

    fun loadDenylist(context: Context) {
        try {
            val file = File(context.filesDir, DENYLIST_FILENAME)

            if (!file.exists()) {
                Log.d(TAG, "File denylist non esistente, inizializzo template con domini di test")
                val template = """
                    # Guardian DNS denylist
                    malware-test.com
                    tracking-service.net
                    ads.google.com
                """.trimIndent()

                file.writeText(template)
            }

            val lines = file.readLines()
            denylist = lines
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .map { it.trimEnd('.').lowercase(Locale.ROOT) }
                .toSet()

            Log.d(TAG, "Denylist caricata: ${denylist.size} domini attivi.")
        } catch (e: Exception) {
            Log.e(TAG, "Errore durante il caricamento denylist", e)
        }
    }

    fun addDomain(context: Context, domain: String): Boolean {
        val cleaned = domain.trim().lowercase(Locale.ROOT)
        if (cleaned.isEmpty() || cleaned.startsWith("#")) return false

        val file = File(context.filesDir, DENYLIST_FILENAME)
        if (!denylist.contains(cleaned)) {
            file.appendText("\n$cleaned")
            loadDenylist(context)
            return true
        }
        return false
    }

    fun removeDomain(context: Context, domain: String): Boolean {
        val cleaned = domain.trim().lowercase(Locale.ROOT)
        val file = File(context.filesDir, DENYLIST_FILENAME)
        if (!file.exists()) return false

        val lines = file.readLines()
        val newLines = lines.filter { it.trim().lowercase(Locale.ROOT) != cleaned }

        if (lines.size == newLines.size) return false

        file.writeText(newLines.joinToString("\n"))
        loadDenylist(context)
        return true
    }
}