package com.werebug.anmapwrapper.parser

import android.os.Bundle
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.werebug.anmapwrapper.MainActivity
import com.werebug.anmapwrapper.R
import java.io.File

class ParserActivity : AppCompatActivity() {

    private lateinit var hostAdapter: HostAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_parser)

        val recyclerView = findViewById<RecyclerView>(R.id.hostListRecyclerView)
        recyclerView.layoutManager = LinearLayoutManager(this)

        // CORREZIONE 1: Aggiunto "MainActivity." davanti per vedere la costante
        val file = File(filesDir, MainActivity.XML_OUTPUT_FILE)

        // CORREZIONE 2: Se NmapParser ti da errore rosso, significa che quella classe
        // deve essere importata o creata. Per ora usiamo una lista vuota per far compilare.
        val hosts: List<Host> = if (file.exists()) {
            try {
                XMLOutputParser().parse(file.inputStream())
            } catch (e: Exception) {
                emptyList()
            }
        } else {
            emptyList()
        }

        // CORREZIONE 3: Explicit type per evitare "Cannot infer type"
        hostAdapter = HostAdapter(hosts)
        recyclerView.adapter = hostAdapter

        supportActionBar?.setDisplayHomeAsUpEnabled(true)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            onBackPressedDispatcher.onBackPressed()
            return true
        }
        return super.onOptionsItemSelected(item)
    }
}