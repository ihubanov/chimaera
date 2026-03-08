package com.torproxy;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class BootReceiver extends BroadcastReceiver {
    private static final String PREFS_NAME = "torproxy_prefs";
    private static final String PREF_APPS = "selected_apps";

    @Override
    public void onReceive(Context context, Intent intent) {
        // Start API service
        Intent apiIntent = new Intent(context, ApiService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(apiIntent);
        } else {
            context.startService(apiIntent);
        }

        // Start built-in Tor
        TorManager.startTor(context);

        // Auto-start VPN with saved app list
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        Set<String> apps = prefs.getStringSet(PREF_APPS, null);
        if (apps != null && !apps.isEmpty()) {
            ArrayList<String> appList = new ArrayList<>(apps);
            Intent vpnIntent = new Intent(context, TorVpnService.class);
            vpnIntent.setAction(TorVpnService.ACTION_START);
            vpnIntent.putStringArrayListExtra(TorVpnService.EXTRA_APPS, appList);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(vpnIntent);
            } else {
                context.startService(vpnIntent);
            }
            Log.i("TorVPN-Boot", "Auto-starting VPN with " + appList.size() + " apps");
        }
    }
}
