package com.torproxy;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class TorManager {
    private static final String TAG = "TorVPN-TorManager";
    private static final int CONTROL_PORT = 9051;
    private static volatile boolean torReady = false;
    private static volatile boolean dormant = false;
    private static volatile int socksPort = 9050;
    private static File cookieFile;
    private static Process torProcess;
    private static Thread monitorThread;

    public static boolean isTorReady() { return torReady; }
    public static int getSocksPort() { return socksPort; }

    public static synchronized void startTor(Context context) {
        if (torProcess != null) {
            // Already running, check if still alive
            try {
                torProcess.exitValue();
                // Process ended, restart
                torProcess = null;
                torReady = false;
            } catch (IllegalThreadStateException e) {
                // Still running
                Log.i(TAG, "Tor already running");
                return;
            }
        }

        File torBinary = findTorBinary(context);
        if (torBinary == null) {
            Log.e(TAG, "Tor binary not found!");
            return;
        }

        File dataDir = new File(context.getFilesDir(), "tor_data");
        if (!dataDir.exists()) dataDir.mkdirs();

        File torrc = new File(context.getFilesDir(), "torrc");
        writeTorrc(torrc, dataDir);

        try {
            ProcessBuilder pb = new ProcessBuilder(
                torBinary.getAbsolutePath(),
                "-f", torrc.getAbsolutePath()
            );
            pb.redirectErrorStream(true);
            pb.directory(context.getFilesDir());
            torProcess = pb.start();
            Log.i(TAG, "Tor process started (pid pending)");

            // Monitor Tor output for bootstrap completion
            monitorThread = new Thread(() -> monitorTor(torProcess), "TorMonitor");
            monitorThread.start();
        } catch (Exception e) {
            Log.e(TAG, "Failed to start Tor", e);
        }
    }

    /**
     * Request a new Tor circuit (new exit IP).
     * Returns a status message.
     */
    public static String newIdentity() {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress("127.0.0.1", CONTROL_PORT), 3000);
            socket.setSoTimeout(5000);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            OutputStream out = socket.getOutputStream();

            // Authenticate with cookie (no greeting — client speaks first)
            byte[] cookie = new byte[32];
            try (FileInputStream fis = new FileInputStream(cookieFile)) {
                fis.read(cookie);
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : cookie) hex.append(String.format("%02X", b));

            out.write(("AUTHENTICATE " + hex.toString() + "\r\n").getBytes());
            out.flush();
            String authResp = in.readLine();
            Log.d(TAG, "Auth: " + authResp);
            if (!authResp.startsWith("250")) {
                return "Auth failed: " + authResp;
            }

            // Send NEWNYM signal
            out.write("SIGNAL NEWNYM\r\n".getBytes());
            out.flush();
            String nymResp = in.readLine();
            Log.d(TAG, "NEWNYM: " + nymResp);

            out.write("QUIT\r\n".getBytes());
            out.flush();

            if (nymResp.startsWith("250")) {
                Log.i(TAG, "New Tor identity requested");
                return "OK";
            } else {
                return "Failed: " + nymResp;
            }
        } catch (Exception e) {
            Log.e(TAG, "newIdentity failed", e);
            return "Error: " + e.getMessage();
        } finally {
            if (socket != null) try { socket.close(); } catch (Exception ignored) {}
        }
    }

    /**
     * Put Tor into dormant mode — stops building circuits, reduces CPU/network.
     * Tor will wake automatically on the next SOCKS connection, but we also
     * signal ACTIVE explicitly for faster response.
     */
    public static void setDormant(boolean enterDormant) {
        if (dormant == enterDormant) return;
        String signal = enterDormant ? "SIGNAL DORMANT" : "SIGNAL ACTIVE";
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress("127.0.0.1", CONTROL_PORT), 2000);
            socket.setSoTimeout(3000);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            OutputStream out = socket.getOutputStream();

            byte[] cookie = new byte[32];
            try (FileInputStream fis = new FileInputStream(cookieFile)) {
                fis.read(cookie);
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : cookie) hex.append(String.format("%02X", b));

            out.write(("AUTHENTICATE " + hex.toString() + "\r\n").getBytes());
            out.flush();
            String authResp = in.readLine();
            if (authResp == null || !authResp.startsWith("250")) return;

            out.write((signal + "\r\n").getBytes());
            out.flush();
            String resp = in.readLine();

            out.write("QUIT\r\n".getBytes());
            out.flush();

            if (resp != null && resp.startsWith("250")) {
                dormant = enterDormant;
                Log.i(TAG, "Tor " + (enterDormant ? "DORMANT" : "ACTIVE"));
            }
        } catch (Exception e) {
            Log.d(TAG, "setDormant failed: " + e.getMessage());
        } finally {
            if (socket != null) try { socket.close(); } catch (Exception ignored) {}
        }
    }

    public static boolean isDormant() { return dormant; }

    public static synchronized void stopTor(Context context) {
        torReady = false;
        if (torProcess != null) {
            torProcess.destroy();
            torProcess = null;
            Log.i(TAG, "Tor process stopped");
        }
    }

    private static void monitorTor(Process process) {
        try {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    Log.d(TAG, "Tor: " + line);
                    if (line.contains("Bootstrapped 100%") || line.contains("Done")) {
                        torReady = true;
                        Log.i(TAG, "Tor bootstrapped! SOCKS port: " + socksPort);
                    }
                }
            } finally {
                reader.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Tor monitor error", e);
        }
        torReady = false;
        Log.i(TAG, "Tor process ended");
    }

    private static File findTorBinary(Context context) {
        // The tor-android AAR puts libtor.so in the native libs directory
        String nativeLibDir = context.getApplicationInfo().nativeLibraryDir;
        File torBin = new File(nativeLibDir, "libtor.so");
        if (torBin.exists() && torBin.canExecute()) {
            Log.i(TAG, "Found tor binary at " + torBin.getAbsolutePath());
            return torBin;
        }
        Log.e(TAG, "Tor binary not found at " + torBin.getAbsolutePath());
        return null;
    }

    private static void writeTorrc(File torrc, File dataDir) {
        try (FileWriter writer = new FileWriter(torrc)) {
            cookieFile = new File(dataDir, "control_auth_cookie");
            writer.write("SocksPort 9050\n");
            writer.write("ControlPort 9051\n");
            writer.write("CookieAuthentication 1\n");
            writer.write("CookieAuthFile " + cookieFile.getAbsolutePath() + "\n");
            writer.write("DataDirectory " + dataDir.getAbsolutePath() + "\n");
            writer.write("AvoidDiskWrites 1\n");
            writer.write("SafeLogging 1\n");
            writer.write("Log notice stdout\n");
            // Battery optimizations
            writer.write("DormantCanceledByStartup 1\n");     // Start active, go dormant when idle
            writer.write("DormantOnFirstStartup 0\n");        // Don't start dormant
            writer.write("DormantTimeoutEnabled 1\n");        // Auto-dormant after inactivity
            writer.write("MaxCircuitDirtiness 600\n");        // Reuse circuits longer (10 min vs 10 min default)
            writer.write("LearnCircuitBuildTimeout 1\n");     // Adapt circuit build timing
            writer.write("CircuitBuildTimeout 30\n");         // Don't wait too long for slow circuits
            writer.write("KeepalivePeriod 120\n");            // Less frequent keepalives (2 min)
            writer.write("NewCircuitPeriod 120\n");           // Build new circuits less often when idle
            Log.i(TAG, "Wrote torrc to " + torrc.getAbsolutePath());
        } catch (Exception e) {
            Log.e(TAG, "Failed to write torrc", e);
        }
    }
}
