package com.werebug.anmapwrapper

import android.app.Application
import android.util.Log

class GuardianApplication : Application() {

    companion object {
        private const val TAG = "GuardianApplication"
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "🛡️ Guardian MTD Security Context Initialized.")
    }
}