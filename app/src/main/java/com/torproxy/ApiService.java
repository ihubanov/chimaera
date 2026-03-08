package com.torproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;
import android.provider.Settings;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ApiService extends Service {
    private static final String TAG = "TorVPN-API";
    private static final int BASE_PORT = 8750;
    private static final String PREFS_NAME = "torproxy_prefs";
    private static final String PREF_APPS = "selected_apps";

    private ServerSocket serverSocket;
    private volatile boolean running;
    private Thread serverThread;
    private ExecutorService requestExecutor;

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!running) {
            running = true;
            requestExecutor = Executors.newFixedThreadPool(4);
            setupNotification();
            int port = BASE_PORT + getUserId();
            serverThread = new Thread(() -> runServer(port), "API-Server");
            serverThread.start();
            Log.i(TAG, "API server starting on port " + port + " (user " + getUserId() + ")");
        }
        return START_STICKY;
    }

    private int getUserId() {
        return android.os.Process.myUid() / 100000;
    }

    private void runServer(int port) {
        try {
            serverSocket = new ServerSocket(port, 5, InetAddress.getByName("127.0.0.1"));
            while (running) {
                try {
                    Socket client = serverSocket.accept();
                    client.setSoTimeout(5000);
                    handleRequest(client);
                } catch (IOException e) {
                    if (running) Log.e(TAG, "Accept error", e);
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Server start failed on port " + port, e);
        }
    }

    private void handleRequest(Socket client) {
        requestExecutor.execute(() -> {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
                String requestLine = reader.readLine();
                if (requestLine == null) { client.close(); return; }

                // Read headers (consume them)
                String line;
                int contentLength = 0;
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    if (line.toLowerCase().startsWith("content-length:")) {
                        contentLength = Integer.parseInt(line.substring(15).trim());
                    }
                }

                String[] parts = requestLine.split(" ");
                if (parts.length < 2) { client.close(); return; }
                String method = parts[0];
                String path = parts[1];

                String response = route(method, path);
                sendResponse(client, 200, response);
            } catch (Exception e) {
                try {
                    sendResponse(client, 500, "{\"error\":\"" + e.getMessage() + "\"}");
                } catch (IOException ignored) {}
            }
        });
    }

    private String route(String method, String path) {
        String query = "";
        if (path.contains("?")) {
            query = path.substring(path.indexOf("?") + 1);
            path = path.substring(0, path.indexOf("?"));
        }

        switch (path) {
            case "/status":
                return getStatus();
            case "/start":
                if ("POST".equals(method)) return startVpn();
                return "{\"error\":\"use POST\"}";
            case "/stop":
                if ("POST".equals(method)) return stopVpn();
                return "{\"error\":\"use POST\"}";
            case "/apps":
                return getApps();
            case "/apps/add":
                if ("POST".equals(method)) return addApp(getParam(query, "pkg"));
                return "{\"error\":\"use POST\"}";
            case "/apps/remove":
                if ("POST".equals(method)) return removeApp(getParam(query, "pkg"));
                return "{\"error\":\"use POST\"}";
            case "/always-on":
                if ("POST".equals(method)) {
                    boolean enabled = "true".equals(getParam(query, "enabled"));
                    boolean lockdown = "true".equals(getParam(query, "lockdown"));
                    return setAlwaysOn(enabled, lockdown);
                }
                return getAlwaysOn();
            default:
                return "{\"error\":\"unknown endpoint\",\"endpoints\":[\"/status\",\"/start\",\"/stop\",\"/apps\",\"/apps/add?pkg=x\",\"/apps/remove?pkg=x\",\"/always-on\",\"/always-on?enabled=true&lockdown=true\"]}";
        }
    }

    private String getParam(String query, String key) {
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && kv[0].equals(key)) return kv[1];
        }
        return "";
    }

    private String getStatus() {
        boolean vpnRunning = TorVpnService.isRunning();
        int userId = getUserId();
        return "{\"running\":" + vpnRunning + ",\"user\":" + userId + ",\"port\":" + (BASE_PORT + userId) + "}";
    }

    private String startVpn() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        Set<String> apps = prefs.getStringSet(PREF_APPS, null);
        ArrayList<String> appList = new ArrayList<>();
        if (apps != null) appList.addAll(apps);
        if (appList.isEmpty()) appList.add("io.metamask");

        Intent intent = new Intent(this, TorVpnService.class);
        intent.setAction(TorVpnService.ACTION_START);
        intent.putStringArrayListExtra(TorVpnService.EXTRA_APPS, appList);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        return "{\"ok\":true,\"action\":\"start\",\"apps\":" + appList.size() + "}";
    }

    private String stopVpn() {
        Intent intent = new Intent(this, TorVpnService.class);
        intent.setAction(TorVpnService.ACTION_STOP);
        startService(intent);
        return "{\"ok\":true,\"action\":\"stop\"}";
    }

    private String getApps() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        Set<String> apps = prefs.getStringSet(PREF_APPS, new HashSet<>());
        StringBuilder sb = new StringBuilder("{\"apps\":[");
        boolean first = true;
        for (String app : apps) {
            if (!first) sb.append(",");
            sb.append("\"").append(app).append("\"");
            first = false;
        }
        sb.append("]}");
        return sb.toString();
    }

    private String addApp(String pkg) {
        if (pkg == null || pkg.isEmpty()) return "{\"error\":\"missing pkg parameter\"}";
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        Set<String> apps = new HashSet<>(prefs.getStringSet(PREF_APPS, new HashSet<>()));
        apps.add(pkg);
        prefs.edit().putStringSet(PREF_APPS, apps).apply();
        return "{\"ok\":true,\"action\":\"add\",\"pkg\":\"" + pkg + "\"}";
    }

    private String removeApp(String pkg) {
        if (pkg == null || pkg.isEmpty()) return "{\"error\":\"missing pkg parameter\"}";
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        Set<String> apps = new HashSet<>(prefs.getStringSet(PREF_APPS, new HashSet<>()));
        apps.remove(pkg);
        prefs.edit().putStringSet(PREF_APPS, apps).apply();
        return "{\"ok\":true,\"action\":\"remove\",\"pkg\":\"" + pkg + "\"}";
    }

    private String getAlwaysOn() {
        try {
            // Read via shell since Settings.Secure.getString can't read @hide keys
            String app = shellGet("settings get secure always_on_vpn_app");
            String lockdown = shellGet("settings get secure always_on_vpn_lockdown");
            boolean enabled = "com.torproxy".equals(app);
            boolean locked = "1".equals(lockdown);
            return "{\"always_on\":" + enabled + ",\"lockdown\":" + locked + "}";
        } catch (Exception e) {
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    private String shellGet(String cmd) {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(cmd.split(" "));
            p.waitFor();
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
            String result = r.readLine();
            r.close();
            if (result != null) result = result.trim();
            return (result != null && !result.isEmpty() && !result.equals("null")) ? result : "";
        } catch (Exception e) {
            return "";
        } finally {
            if (p != null) p.destroy();
        }
    }

    private String setAlwaysOn(boolean enabled, boolean lockdown) {
        try {
            if (enabled) {
                Settings.Secure.putString(getContentResolver(), "always_on_vpn_app", "com.torproxy");
                Settings.Secure.putString(getContentResolver(), "always_on_vpn_lockdown", lockdown ? "1" : "0");
            } else {
                Settings.Secure.putString(getContentResolver(), "always_on_vpn_app", null);
                Settings.Secure.putString(getContentResolver(), "always_on_vpn_lockdown", null);
            }
            return "{\"ok\":true,\"always_on\":" + enabled + ",\"lockdown\":" + lockdown + "}";
        } catch (Exception e) {
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    private void sendResponse(Socket client, int code, String body) throws IOException {
        OutputStream out = client.getOutputStream();
        String status = code == 200 ? "OK" : "Error";
        String response = "HTTP/1.1 " + code + " " + status + "\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: " + body.length() + "\r\n" +
            "Connection: close\r\n" +
            "\r\n" + body;
        out.write(response.getBytes());
        out.flush();
        client.close();
    }

    private void setupNotification() {
        String channelId = "tor_api";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                channelId, "TorProxy API", NotificationManager.IMPORTANCE_MIN);
            getSystemService(NotificationManager.class).createNotificationChannel(channel);
        }

        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nb = new Notification.Builder(this, channelId);
        } else {
            nb = new Notification.Builder(this);
        }

        Notification notification = nb
            .setContentTitle("TorProxy API")
            .setContentText("API running on port " + (BASE_PORT + getUserId()))
            .setSmallIcon(android.R.drawable.ic_menu_manage)
            .setOngoing(true)
            .build();

        startForeground(2, notification);
    }

    @Override
    public void onDestroy() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        if (requestExecutor != null) requestExecutor.shutdownNow();
        super.onDestroy();
    }
}
