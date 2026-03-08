package com.torproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity {
    private static final int VPN_REQUEST_CODE = 1;
    private static final String PREFS_NAME = "torproxy_prefs";
    private static final String PREF_APPS = "selected_apps";
    private static final int MAX_LOG_LINES = 200;
    private boolean vpnRunning = false;
    private Button startButton, stopButton, addAppButton, checkIpButton, newIdentityButton;
    private TextView statusText, torIpText, logText;
    private android.widget.ScrollView logScrollView;
    private ListView appListView;
    private CheckBox alwaysOnCheck, lockdownCheck;
    private final ArrayList<String> selectedApps = new ArrayList<>();
    private AppListAdapter appAdapter;
    private final StringBuilder logBuffer = new StringBuilder();
    private int logLineCount = 0;

    private boolean autoCheckedIp = false;

    private final BroadcastReceiver trafficReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String msg = intent.getStringExtra(TorVpnService.EXTRA_MESSAGE);
            if (msg != null) appendLog(msg);
        }
    };

    private void appendLog(String line) {
        String time = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
                .format(new java.util.Date());
        logBuffer.append(time).append("  ").append(line).append('\n');
        logLineCount++;
        if (logLineCount > MAX_LOG_LINES) {
            int idx = logBuffer.indexOf("\n");
            if (idx >= 0) logBuffer.delete(0, idx + 1);
            logLineCount--;
        }
        logText.setText(logBuffer.toString());
        logScrollView.post(() -> logScrollView.fullScroll(View.FOCUS_DOWN));
    }

    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            // Always read the latest status from the service
            statusText.setText("> status: " + TorVpnService.getStatus());
            statusText.setTextColor(TorVpnService.getStatusColor());
            boolean wasRunning = vpnRunning;
            vpnRunning = TorVpnService.isRunning();
            updateButtons();
            // Auto check IP when VPN just became active
            String status = TorVpnService.getStatus();
            if (vpnRunning && status.contains("ACTIVE") && !autoCheckedIp) {
                autoCheckedIp = true;
                checkTorIp();
            }
            // Reset flag when VPN stops
            if (!vpnRunning) {
                autoCheckedIp = false;
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if (getActionBar() != null) getActionBar().setTitle("[ Chimæra ]");

        startButton = findViewById(R.id.startButton);
        stopButton = findViewById(R.id.stopButton);
        addAppButton = findViewById(R.id.addAppButton);
        checkIpButton = findViewById(R.id.checkIpButton);
        newIdentityButton = findViewById(R.id.newIdentityButton);
        torIpText = findViewById(R.id.torIpText);
        statusText = findViewById(R.id.statusText);
        logText = findViewById(R.id.logText);
        logScrollView = findViewById(R.id.logScrollView);
        appListView = findViewById(R.id.appList);
        alwaysOnCheck = findViewById(R.id.alwaysOnCheck);
        lockdownCheck = findViewById(R.id.lockdownCheck);

        loadSelectedApps();
        appAdapter = new AppListAdapter();
        appListView.setAdapter(appAdapter);

        startButton.setOnClickListener(v -> startVpn());
        stopButton.setOnClickListener(v -> stopVpn());
        addAppButton.setOnClickListener(v -> showAppPicker());
        checkIpButton.setOnClickListener(v -> checkTorIp());
        newIdentityButton.setOnClickListener(v -> newIdentity());

        // Use OnClickListener instead of OnCheckedChangeListener
        // OnClick only fires on USER taps, not programmatic setChecked()
        alwaysOnCheck.setOnClickListener(v -> applyAlwaysOn());
        lockdownCheck.setOnClickListener(v -> applyAlwaysOn());

        // Start API service
        Intent apiIntent = new Intent(this, ApiService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(apiIntent);
        } else {
            startService(apiIntent);
        }

        updateButtons();
    }

    @Override
    protected void onResume() {
        super.onResume();
        IntentFilter filter = new IntentFilter(TorVpnService.ACTION_LOG);
        IntentFilter trafficFilter = new IntentFilter(TorVpnService.ACTION_TRAFFIC);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
            registerReceiver(trafficReceiver, trafficFilter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(statusReceiver, filter);
            registerReceiver(trafficReceiver, trafficFilter);
        }
        vpnRunning = TorVpnService.isRunning();
        updateButtons();
        statusText.setText("> status: " + TorVpnService.getStatus());
        statusText.setTextColor(TorVpnService.getStatusColor());
        loadAlwaysOnState();
    }

    @Override
    protected void onPause() {
        super.onPause();
        unregisterReceiver(statusReceiver);
        unregisterReceiver(trafficReceiver);
    }

    private void updateButtons() {
        boolean isBlocked = TorVpnService.isBlocked();
        startButton.setEnabled(!vpnRunning);
        startButton.setText("[ START VPN ]");
        stopButton.setEnabled(vpnRunning);
        checkIpButton.setEnabled(vpnRunning);
        newIdentityButton.setEnabled(vpnRunning);

        // Active: bright text + lit background + border | Disabled: dim and dead
        styleButton(startButton, 0xFF00FF41, 0xFF0D1F0D, 0xFF00FF41);  // green
        styleButton(stopButton, 0xFFFF3333, 0xFF1F0D0D, 0xFFFF3333);   // red
        styleButton(checkIpButton, 0xFF00CCFF, 0xFF0D1520, 0xFF00CCFF); // cyan
        styleButton(newIdentityButton, 0xFFFFAA00, 0xFF1A1500, 0xFFFFAA00); // orange
        styleButton(addAppButton, 0xFF00CCFF, 0xFF0D1520, 0xFF00CCFF);  // cyan (always enabled)
    }

    private void styleButton(Button btn, int activeTextColor, int activeBgColor, int borderColor) {
        if (btn.isEnabled()) {
            btn.setTextColor(activeTextColor);
            btn.setAlpha(1.0f);
            // Lit border + dark fill
            android.graphics.drawable.GradientDrawable bg = new android.graphics.drawable.GradientDrawable();
            bg.setColor(activeBgColor);
            bg.setStroke(2, borderColor);
            bg.setCornerRadius(4);
            btn.setBackground(bg);
        } else {
            btn.setTextColor(0xFF333333);
            btn.setAlpha(0.6f);
            // No border, very dark fill
            android.graphics.drawable.GradientDrawable bg = new android.graphics.drawable.GradientDrawable();
            bg.setColor(0xFF0A0A0A);
            bg.setStroke(1, 0xFF1A1A1A);
            bg.setCornerRadius(4);
            btn.setBackground(bg);
        }
    }

    // --- Tor IP check ---

    private void checkTorIp() {
        checkIpButton.setEnabled(false);
        checkIpButton.setText("[ ... ]");
        torIpText.setVisibility(View.VISIBLE);
        torIpText.setText("> connecting via socks5 proxy...");
        torIpText.setTextColor(0xFFFFAA00);

        new Thread(() -> {
            String torIp = null;
            String directIp = null;
            try {
                // Connect through Tor SOCKS5 proxy (fresh connection, no pooling)
                java.net.Proxy proxy = new java.net.Proxy(java.net.Proxy.Type.SOCKS,
                    new java.net.InetSocketAddress("127.0.0.1", TorManager.getSocksPort()));
                HttpURLConnection conn = (HttpURLConnection) new URL("https://api.ipify.org?t=" + System.nanoTime()).openConnection(proxy);
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(10000);
                conn.setUseCaches(false);
                conn.setRequestProperty("Connection", "close");
                BufferedReader r = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                torIp = r.readLine();
                r.close();
                conn.disconnect();
            } catch (Exception e) {
                torIp = "ERROR: " + e.getMessage();
            }

            try {
                // Direct connection (your real IP)
                HttpURLConnection conn = (HttpURLConnection) new URL("https://api.ipify.org?t=" + System.nanoTime()).openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.setUseCaches(false);
                conn.setRequestProperty("Connection", "close");
                BufferedReader r = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                directIp = r.readLine();
                r.close();
                conn.disconnect();
            } catch (Exception e) {
                directIp = "unavailable";
            }

            String finalTorIp = torIp;
            String finalDirectIp = directIp;
            runOnUiThread(() -> {
                checkIpButton.setEnabled(true);
                checkIpButton.setText("[ CHECK IP ]");
                boolean isTor = finalTorIp != null && !finalTorIp.startsWith("ERROR")
                    && !finalTorIp.equals(finalDirectIp);
                if (isTor) {
                    torIpText.setText("> exit_node: " + finalTorIp + "\n> real_ip:   " + finalDirectIp + "\n> status:    MASKED");
                    torIpText.setTextColor(0xFF00FF41);
                } else {
                    torIpText.setText("> tor_ip:  " + finalTorIp + "\n> real_ip: " + finalDirectIp + "\n> status:  EXPOSED");
                    torIpText.setTextColor(0xFFFF3333);
                }
            });
        }).start();
    }

    // --- New Identity ---

    private void newIdentity() {
        newIdentityButton.setEnabled(false);
        newIdentityButton.setText("[ ... ]");
        torIpText.setVisibility(View.VISIBLE);
        torIpText.setText("> signal NEWNYM sent...");
        torIpText.setTextColor(0xFFFFAA00);

        new Thread(() -> {
            String result = TorManager.newIdentity();
            if ("OK".equals(result)) {
                // Close all existing connections so apps are forced through new circuit
                TorVpnService.closeAllSessions();
                // Wait for Tor to build new circuits (rate limit is ~10s)
                for (int i = 8; i > 0; i--) {
                    int sec = i;
                    runOnUiThread(() -> torIpText.setText("> building_circuit... " + sec + "s"));
                    try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
                }
                runOnUiThread(() -> {
                    newIdentityButton.setEnabled(true);
                    newIdentityButton.setText("[ NEW IDENTITY ]");
                    // Auto check the new IP
                    checkTorIp();
                });
            } else {
                runOnUiThread(() -> {
                    newIdentityButton.setEnabled(true);
                    newIdentityButton.setText("[ NEW IDENTITY ]");
                    torIpText.setText("> ERROR: identity_change_failed\n> " + result);
                    torIpText.setTextColor(0xFFFF3333);
                });
            }
        }).start();
    }

    // --- Always-on VPN ---

    private void loadAlwaysOnState() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        alwaysOnCheck.setChecked(prefs.getBoolean("always_on", false));
        lockdownCheck.setChecked(prefs.getBoolean("lockdown", false));
    }

    private void applyAlwaysOn() {
        boolean enabled = alwaysOnCheck.isChecked();
        boolean lockdown = lockdownCheck.isChecked();
        try {
            if (enabled) {
                Settings.Secure.putString(getContentResolver(), "always_on_vpn_app", "com.torproxy");
                Settings.Secure.putString(getContentResolver(), "always_on_vpn_lockdown", lockdown ? "1" : "0");
            } else {
                Settings.Secure.putString(getContentResolver(), "always_on_vpn_app", null);
                Settings.Secure.putString(getContentResolver(), "always_on_vpn_lockdown", null);
            }
            // Save to prefs so we can read it back (can't read @hide secure settings)
            getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                .putBoolean("always_on", enabled)
                .putBoolean("lockdown", lockdown)
                .apply();
        } catch (Exception e) {
            statusText.setText("ERROR: " + e.getMessage());
            statusText.setTextColor(0xFFFF0000);
            // Revert checkboxes
            alwaysOnCheck.setChecked(!enabled);
        }
    }

    // --- App management ---

    private void loadSelectedApps() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        Set<String> apps = prefs.getStringSet(PREF_APPS, null);
        selectedApps.clear();
        if (apps != null) {
            selectedApps.addAll(apps);
        } else {
            selectedApps.add("io.metamask");
            saveSelectedApps();
        }
        Collections.sort(selectedApps);
    }

    private void saveSelectedApps() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        prefs.edit().putStringSet(PREF_APPS, new HashSet<>(selectedApps)).apply();
    }

    private void showAppPicker() {
        PackageManager pm = getPackageManager();
        List<AppEntry> appEntries = new ArrayList<>();
        List<AppEntry> filtered = new ArrayList<>();

        android.widget.LinearLayout layout = new android.widget.LinearLayout(this);
        layout.setOrientation(android.widget.LinearLayout.VERTICAL);
        layout.setPadding(32, 16, 32, 0);

        android.widget.EditText search = new android.widget.EditText(this);
        search.setHint("Search or type package name...");
        search.setSingleLine(true);
        search.setTextSize(14);
        layout.addView(search);

        TextView loadingText = new TextView(this);
        loadingText.setText("> scanning_packages...");
        loadingText.setTextSize(14);
        loadingText.setTypeface(android.graphics.Typeface.MONOSPACE);
        loadingText.setPadding(0, 24, 0, 24);
        loadingText.setTextColor(0xFF00FF41);
        layout.addView(loadingText);

        ListView listView = new ListView(this);
        listView.setPadding(0, 8, 0, 0);
        listView.setVisibility(View.GONE);
        layout.addView(listView, new android.widget.LinearLayout.LayoutParams(
            android.widget.LinearLayout.LayoutParams.MATCH_PARENT, 800));

        BaseAdapter pickerAdapter = new BaseAdapter() {
            @Override public int getCount() { return filtered.size(); }
            @Override public Object getItem(int pos) { return filtered.get(pos); }
            @Override public long getItemId(int pos) { return pos; }
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                if (convertView == null) {
                    convertView = LayoutInflater.from(MainActivity.this)
                        .inflate(R.layout.app_list_item, parent, false);
                    convertView.findViewById(R.id.removeButton).setVisibility(View.GONE);
                }
                AppEntry entry = filtered.get(position);
                ((TextView) convertView.findViewById(R.id.appName)).setText(entry.label);
                ((TextView) convertView.findViewById(R.id.appPackage)).setText(entry.packageName);
                ImageView icon = convertView.findViewById(R.id.appIcon);
                if (entry.info != null) {
                    icon.setImageDrawable(pm.getApplicationIcon(entry.info));
                } else {
                    icon.setImageResource(android.R.drawable.sym_def_app_icon);
                }
                return convertView;
            }
        };
        listView.setAdapter(pickerAdapter);

        AlertDialog dialog = new AlertDialog.Builder(this)
            .setTitle("Select app to route through Tor")
            .setView(layout)
            .setNeutralButton("Add by package name", null)
            .setNegativeButton("Cancel", null)
            .create();

        listView.setOnItemClickListener((parent, view, position, id) -> {
            addAppByPackage(filtered.get(position).packageName);
            dialog.dismiss();
        });

        search.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override
            public void afterTextChanged(android.text.Editable s) {
                String q = s.toString().toLowerCase().trim();
                filtered.clear();
                if (q.isEmpty()) {
                    filtered.addAll(appEntries);
                } else {
                    for (AppEntry e : appEntries) {
                        if (e.label.toLowerCase().contains(q) || e.packageName.toLowerCase().contains(q))
                            filtered.add(e);
                    }
                }
                pickerAdapter.notifyDataSetChanged();
            }
        });

        dialog.show();
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
            String typed = search.getText().toString().trim();
            if (!typed.isEmpty() && typed.contains(".")) {
                addAppByPackage(typed);
                dialog.dismiss();
            }
        });

        // Load apps in background, update dialog live
        new Thread(() -> {
            Intent launcherIntent = new Intent(Intent.ACTION_MAIN);
            launcherIntent.addCategory(Intent.CATEGORY_LAUNCHER);
            List<android.content.pm.ResolveInfo> launchable = pm.queryIntentActivities(launcherIntent, 0);
            Set<String> seen = new HashSet<>();
            int total = launchable.size();
            int count = 0;
            for (android.content.pm.ResolveInfo ri : launchable) {
                count++;
                String pkg = ri.activityInfo.packageName;
                if (seen.contains(pkg) || selectedApps.contains(pkg) || pkg.equals(getPackageName())) continue;
                seen.add(pkg);
                try {
                    ApplicationInfo info = pm.getApplicationInfo(pkg, 0);
                    String label = pm.getApplicationLabel(info).toString();
                    appEntries.add(new AppEntry(pkg, label, info));
                } catch (PackageManager.NameNotFoundException ignored) {}
                // Update progress every 20 apps
                if (count % 20 == 0) {
                    int c = count;
                    runOnUiThread(() -> loadingText.setText("> scanning... " + c + "/" + total));
                }
            }
            Collections.sort(appEntries, (a, b) -> a.label.compareToIgnoreCase(b.label));
            runOnUiThread(() -> {
                filtered.addAll(appEntries);
                pickerAdapter.notifyDataSetChanged();
                loadingText.setVisibility(View.GONE);
                listView.setVisibility(View.VISIBLE);
            });
        }).start();
    }

    private void addAppByPackage(String pkg) {
        if (!selectedApps.contains(pkg)) {
            selectedApps.add(pkg);
            Collections.sort(selectedApps);
            saveSelectedApps();
            appAdapter.notifyDataSetChanged();
            restartVpnIfRunning();
        }
    }

    private void removeApp(String packageName) {
        selectedApps.remove(packageName);
        saveSelectedApps();
        appAdapter.notifyDataSetChanged();
        if (selectedApps.isEmpty() && TorVpnService.isBlocked()) {
            Intent intent = new Intent(this, TorVpnService.class);
            intent.setAction(TorVpnService.ACTION_STOP);
            startService(intent);
            statusText.setText("> status: stopped");
            statusText.setTextColor(0xFFAAAAAA);
            updateButtons();
        } else {
            restartVpnIfRunning();
        }
    }

    private void restartVpnIfRunning() {
        if (vpnRunning || TorVpnService.isRunning() || TorVpnService.isBlocked()) {
            // Restart VPN with updated app list
            autoCheckedIp = false;
            launchVpnService();
        }
    }

    static class AppEntry {
        String packageName;
        String label;
        ApplicationInfo info;
        AppEntry(String packageName, String label, ApplicationInfo info) {
            this.packageName = packageName;
            this.label = label;
            this.info = info;
        }
    }

    // --- VPN control ---

    private void startVpn() {
        if (selectedApps.isEmpty()) return;
        Intent prepareIntent;
        try {
            prepareIntent = VpnService.prepare(this);
        } catch (Exception e) {
            return;
        }
        if (prepareIntent == null) {
            launchVpnService();
        } else {
            try {
                startActivityForResult(prepareIntent, VPN_REQUEST_CODE);
            } catch (Exception ignored) {}
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            launchVpnService();
        }
    }

    private void launchVpnService() {
        Intent intent = new Intent(this, TorVpnService.class);
        intent.setAction(TorVpnService.ACTION_START);
        intent.putStringArrayListExtra(TorVpnService.EXTRA_APPS, selectedApps);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        vpnRunning = true;
        updateButtons();
        statusText.setText("> status: initializing...");
        statusText.setTextColor(0xFFFFAA00);
        logBuffer.setLength(0);
        logLineCount = 0;
        logText.setText("> awaiting_connection...");
    }

    private void stopVpn() {
        Intent intent = new Intent(this, TorVpnService.class);
        intent.setAction(TorVpnService.ACTION_DISCONNECT);
        startService(intent);
        vpnRunning = false;
        torIpText.setVisibility(View.GONE);
        updateButtons();
        statusText.setText("> status: BLOCKED — no internet without tor");
        statusText.setTextColor(0xFFFF6600);
        logBuffer.setLength(0);
        logLineCount = 0;
        logText.setText("> connection_terminated");
    }

    private boolean isDualAppInstalled(String pkg) {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(new String[]{"cmd", "package", "list", "packages", "--user", "999", pkg});
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.contains(pkg)) return true;
            }
            r.close();
        } catch (Exception ignored) {
        } finally {
            if (p != null) p.destroy();
        }
        return false;
    }

    // --- App list adapter ---

    private class AppListAdapter extends BaseAdapter {
        @Override public int getCount() { return selectedApps.size(); }
        @Override public String getItem(int pos) { return selectedApps.get(pos); }
        @Override public long getItemId(int pos) { return pos; }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = LayoutInflater.from(MainActivity.this)
                    .inflate(R.layout.app_list_item, parent, false);
            }
            String pkg = selectedApps.get(position);
            ImageView icon = convertView.findViewById(R.id.appIcon);
            TextView name = convertView.findViewById(R.id.appName);
            TextView pkgText = convertView.findViewById(R.id.appPackage);
            Button removeBtn = convertView.findViewById(R.id.removeButton);

            PackageManager pm = getPackageManager();
            try {
                ApplicationInfo info = pm.getApplicationInfo(pkg, 0);
                String label = pm.getApplicationLabel(info).toString();
                name.setText(label);
                icon.setImageDrawable(pm.getApplicationIcon(info));
            } catch (PackageManager.NameNotFoundException e) {
                name.setText(pkg);
                icon.setImageResource(android.R.drawable.sym_def_app_icon);
            }
            pkgText.setText(pkg);
            removeBtn.setEnabled(true);
            removeBtn.setVisibility(View.VISIBLE);
            removeBtn.setOnClickListener(v -> removeApp(pkg));
            return convertView;
        }
    }
}
