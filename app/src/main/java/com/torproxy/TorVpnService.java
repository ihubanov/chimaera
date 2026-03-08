package com.torproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TorVpnService extends VpnService {
    private static final String TAG = "TorVPN";
    private static final String VPN_ADDRESS = "10.0.0.2";
    private static final int VPN_MTU = 1400;
    private static final String SOCKS_HOST = "127.0.0.1";
    public static final String ACTION_START = "START";
    public static final String ACTION_STOP = "STOP";
    public static final String ACTION_DISCONNECT = "DISCONNECT";
    public static final String ACTION_LOG = "com.torproxy.LOG";
    public static final String ACTION_TRAFFIC = "com.torproxy.TRAFFIC";
    public static final String EXTRA_MESSAGE = "message";
    public static final String EXTRA_APPS = "apps";

    private static volatile boolean sRunning;
    private static volatile boolean sBlocked;
    private static volatile String sStatus = "Stopped";
    private static volatile int sStatusColor = 0xFFAAAAAA;

    private ParcelFileDescriptor vpnInterface;
    private FileOutputStream vpnOutput;
    private volatile boolean running;
    private volatile boolean blocked;
    private Thread vpnLoopThread;
    private Thread drainThread;
    private Thread idleWatchThread;
    private volatile long lastPacketTime;
    private static final long IDLE_TIMEOUT_MS = 60_000; // 1 min idle → dormant

    private static TorVpnService instance;

    public static boolean isRunning() { return sRunning; }
    public static boolean isBlocked() { return sBlocked; }
    public static String getStatus() { return sStatus; }
    public static int getStatusColor() { return sStatusColor; }

    public static void closeAllSessions() {
        TorVpnService svc = instance;
        if (svc != null) {
            int count = svc.sessions.size();
            for (TcpSession session : svc.sessions.values()) {
                svc.closeSession(session);
            }
            svc.sessions.clear();
            Log.i(TAG, "Closed " + count + " sessions for identity rotation");
        }
    }

    private void setStatus(String status, int color) {
        sStatus = status;
        sStatusColor = color;
        // Notify UI
        Intent intent = new Intent(ACTION_LOG);
        intent.setPackage(getPackageName());
        intent.putExtra(EXTRA_MESSAGE, status);
        sendBroadcast(intent);
    }
    private final ConcurrentHashMap<String, TcpSession> sessions = new ConcurrentHashMap<>();
    private ExecutorService executor;
    private ArrayList<String> allowedApps;

    static class TcpSession {
        Socket socket;
        InputStream socksIn;
        OutputStream socksOut;
        long mySeqNum;
        long theirSeqNum;
        byte[] remoteAddr;
        int remotePort;
        byte[] localAddr;
        int localPort;
        volatile boolean established;
        volatile boolean closed;
        Thread readerThread;
    }

    private void log(String msg) {
        Log.i(TAG, msg);
    }

    private void logAndBroadcast(String msg) {
        Log.i(TAG, msg);
        Intent intent = new Intent(ACTION_LOG);
        intent.setPackage(getPackageName());
        intent.putExtra(EXTRA_MESSAGE, msg);
        sendBroadcast(intent);
    }

    private void trafficLog(String msg) {
        Intent intent = new Intent(ACTION_TRAFFIC);
        intent.setPackage(getPackageName());
        intent.putExtra(EXTRA_MESSAGE, msg);
        sendBroadcast(intent);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Always ensure API service is running
        try {
            Intent apiIntent = new Intent(this, ApiService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(apiIntent);
            } else {
                startService(apiIntent);
            }
        } catch (Exception ignored) {}

        if (intent == null) {
            // Service restarted by system (START_STICKY) without intent — don't auto-start VPN
            stopSelf();
            return START_NOT_STICKY;
        }

        if (ACTION_STOP.equals(intent.getAction())) {
            // Full stop — tears down VPN tunnel, apps go direct
            stop();
            return START_NOT_STICKY;
        }

        if (ACTION_DISCONNECT.equals(intent.getAction())) {
            // Block mode — keep VPN tunnel up but stop forwarding
            // Selected apps' traffic enters the tunnel but gets dropped
            blocked = true;
            sBlocked = true;
            running = false;
            sRunning = false;
            // Close all active SOCKS sessions
            for (TcpSession session : sessions.values()) {
                closeSession(session);
            }
            sessions.clear();
            if (executor != null) executor.shutdownNow();
            log("VPN blocked — apps cannot access internet");
            setStatus("Stopped — apps blocked (no internet without Tor)", 0xFFFF6600);
            updateNotification("Blocked — apps have no internet");
            if (drainThread != null) drainThread.interrupt();
            drainThread = new Thread(this::drainLoop, "VPN-Drain");
            drainThread.start();
            return START_NOT_STICKY;
        }

        allowedApps = intent.getStringArrayListExtra(EXTRA_APPS);
        if (allowedApps == null || allowedApps.isEmpty()) {
            // Try loading from SharedPreferences (always-on auto-start or boot)
            android.content.SharedPreferences prefs = getSharedPreferences("torproxy_prefs", MODE_PRIVATE);
            java.util.Set<String> saved = prefs.getStringSet("selected_apps", null);
            if (saved != null && !saved.isEmpty()) {
                allowedApps = new ArrayList<>(saved);
                log("Loaded " + allowedApps.size() + " apps from saved config");
            } else {
                log("No apps specified, not starting VPN");
                stopSelf();
                return START_NOT_STICKY;
            }
        }

        start();
        return START_NOT_STICKY;
    }

    private void start() {
        // If already running or blocked, tear down and rebuild with new app list
        if (running || blocked) {
            running = false;
            sRunning = false;
            blocked = false;
            sBlocked = false;
            for (TcpSession session : sessions.values()) {
                closeSession(session);
            }
            sessions.clear();
            if (executor != null) executor.shutdownNow();
            if (vpnInterface != null) {
                try { vpnInterface.close(); } catch (Exception ignored) {}
                vpnInterface = null;
            }
            log("Rebuilding VPN with updated app list");
        }

        instance = this;
        setupNotification();
        setStatus("Starting...", 0xFFFFAA00);
        log("Starting VPN service...");

        // Start built-in Tor
        TorManager.startTor(this);
        log("Starting built-in Tor...");

        try {
            Builder builder = new Builder();
            builder.setSession("Chimæra");
            builder.addAddress(VPN_ADDRESS, 32);
            builder.addRoute("0.0.0.0", 0);
            builder.addDnsServer("8.8.8.8");
            builder.setMtu(VPN_MTU);

            if (allowedApps != null && !allowedApps.isEmpty()) {
                int added = 0;
                for (String pkg : allowedApps) {
                    try {
                        builder.addAllowedApplication(pkg);
                        log("Routing: " + pkg);
                        added++;
                    } catch (Exception e) {
                        log("WARNING: " + pkg + " not installed, skipping");
                    }
                }
                if (added == 0) {
                    log("ERROR: No valid apps to route. Aborting.");
                    stopSelf();
                    return;
                }
                log("Filtering " + added + " app(s) through Tor");
            } else {
                log("WARNING: No apps specified, capturing ALL traffic");
            }

            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                log("ERROR: VPN interface failed to establish (was permission granted?)");
                stopSelf();
                return;
            }

            log("VPN established!");

            // Wait for Tor to be ready (it bootstraps in background)
            // Move Tor wait and VPN loop start to background thread
            // so onStartCommand returns promptly
            vpnOutput = new FileOutputStream(vpnInterface.getFileDescriptor());
            running = true;
            sRunning = true;
            executor = Executors.newFixedThreadPool(8);

            vpnLoopThread = new Thread(() -> {
                setStatus("Waiting for Tor...", 0xFFFFAA00);
                log("Waiting for Tor to connect...");
                for (int i = 0; i < 60; i++) {
                    try {
                        Socket testSocket = new Socket();
                        testSocket.connect(new InetSocketAddress(SOCKS_HOST, TorManager.getSocksPort()), 2000);
                        testSocket.close();
                        log("Tor SOCKS5 proxy ready at port " + TorManager.getSocksPort());
                        setStatus("ACTIVE (Tor connected)", 0xFF00CC00);
                        // Force-stop selected apps to kill pre-existing direct connections
                        // They'll relaunch/reconnect through the VPN tunnel
                        killAppConnections();
                        break;
                    } catch (Exception e) {
                        if (i % 5 == 0) {
                            log("Still waiting for Tor... (" + i + "s) - " + e.getMessage());
                            setStatus("Waiting for Tor... (" + i + "s)", 0xFFFFAA00);
                        }
                        try { Thread.sleep(1000); } catch (InterruptedException ignored) {
                            return;
                        }
                    }
                    if (!running) return;
                }
                log("Listening for packets...");
                vpnLoop();
            }, "VPN-Start");
            vpnLoopThread.start();

        } catch (Exception e) {
            log("ERROR: Failed to start VPN: " + e.getMessage());
            stop();
        }
    }

    private void killAppConnections() {
        if (allowedApps == null) return;
        for (String pkg : allowedApps) {
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"am", "force-stop", pkg});
                p.waitFor();
                p.destroy();
                log("Force-stopped " + pkg + " (killing stale connections)");
            } catch (Exception e) {
                log("Could not force-stop " + pkg + ": " + e.getMessage());
            }
        }
        logAndBroadcast("Killed stale connections for " + allowedApps.size() + " app(s)");
    }

    private void stop() {
        running = false;
        sRunning = false;
        blocked = false;
        sBlocked = false;
        setStatus("Stopped", 0xFFAAAAAA);
        log("Stopping VPN...");
        if (idleWatchThread != null) idleWatchThread.interrupt();
        for (TcpSession session : sessions.values()) {
            closeSession(session);
        }
        sessions.clear();
        if (executor != null) executor.shutdownNow();
        if (vpnOutput != null) {
            try { vpnOutput.close(); } catch (IOException ignored) {}
            vpnOutput = null;
        }
        if (vpnInterface != null) {
            try { vpnInterface.close(); } catch (IOException ignored) {}
            vpnInterface = null;
        }
        TorManager.stopTor(this);
        instance = null;
        stopForeground(true);
        stopSelf();
    }

    private void vpnLoop() {
        FileInputStream vpnInput = new FileInputStream(vpnInterface.getFileDescriptor());
        byte[] buffer = new byte[32768];

        lastPacketTime = System.currentTimeMillis();
        startIdleWatch();

        while (running) {
            try {
                int length = vpnInput.read(buffer);
                if (length <= 0) continue;

                // Wake Tor from dormant if needed
                long now = System.currentTimeMillis();
                if (TorManager.isDormant()) {
                    log("Traffic detected — waking Tor from dormant");
                    executor.execute(() -> TorManager.setDormant(false));
                }
                lastPacketTime = now;

                Packet packet = Packet.parse(buffer, length);
                if (packet == null) continue;

                if (packet.protocol == Packet.PROTO_TCP) {
                    handleTcp(packet);
                } else if (packet.protocol == Packet.PROTO_UDP) {
                    handleUdp(packet);
                }
            } catch (Exception e) {
                if (running) Log.e(TAG, "VPN loop error", e);
            }
        }
    }

    private void startIdleWatch() {
        idleWatchThread = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(30_000); // Check every 30s
                } catch (InterruptedException e) {
                    return;
                }
                if (!running) return;
                long idle = System.currentTimeMillis() - lastPacketTime;
                if (idle >= IDLE_TIMEOUT_MS && !TorManager.isDormant()) {
                    log("No traffic for " + (idle / 1000) + "s — Tor entering dormant mode");
                    TorManager.setDormant(true);
                    updateNotification("Active (Tor idle — saving battery)");
                } else if (idle < IDLE_TIMEOUT_MS && TorManager.isDormant()) {
                    updateNotification("Traffic routed through Tor");
                }
            }
        }, "IdleWatch");
        idleWatchThread.start();
    }

    private String sessionKey(Packet p) {
        return p.srcPort + ">" +
               (p.dstAddr[0] & 0xFF) + "." + (p.dstAddr[1] & 0xFF) + "." +
               (p.dstAddr[2] & 0xFF) + "." + (p.dstAddr[3] & 0xFF) + ":" + p.dstPort;
    }

    private String addrStr(byte[] addr, int port) {
        return (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "." +
               (addr[2] & 0xFF) + "." + (addr[3] & 0xFF) + ":" + port;
    }

    private void handleTcp(Packet packet) {
        String key = sessionKey(packet);

        if ((packet.tcpFlags & Packet.TCP_RST) != 0) {
            TcpSession session = sessions.remove(key);
            if (session != null) closeSession(session);
            return;
        }

        if ((packet.tcpFlags & Packet.TCP_SYN) != 0 && (packet.tcpFlags & Packet.TCP_ACK) == 0) {
            TcpSession session = new TcpSession();
            session.localAddr = packet.srcAddr.clone();
            session.localPort = packet.srcPort;
            session.remoteAddr = packet.dstAddr.clone();
            session.remotePort = packet.dstPort;
            session.theirSeqNum = (packet.seqNum + 1) & 0xFFFFFFFFL;
            session.mySeqNum = System.nanoTime() & 0xFFFFFFFFL;

            String dst = addrStr(session.remoteAddr, session.remotePort);
            log("TCP SYN -> " + dst + " (connecting via Tor...)");
            sessions.put(key, session);
            executor.execute(() -> connectSocks(key, session));
            return;
        }

        TcpSession session = sessions.get(key);
        if (session == null) {
            sendRst(packet);
            return;
        }

        if ((packet.tcpFlags & Packet.TCP_FIN) != 0) {
            session.theirSeqNum = (session.theirSeqNum + 1) & 0xFFFFFFFFL;
            sendTcpPacket(session, Packet.TCP_FIN | Packet.TCP_ACK, null);
            session.mySeqNum = (session.mySeqNum + 1) & 0xFFFFFFFFL;
            log("TCP FIN " + addrStr(session.remoteAddr, session.remotePort));
            sessions.remove(key);
            closeSession(session);
            return;
        }

        if ((packet.tcpFlags & Packet.TCP_ACK) != 0) {
            if (packet.payload != null && packet.payload.length > 0 && session.established) {
                if (packet.seqNum != session.theirSeqNum) {
                    sendTcpPacket(session, Packet.TCP_ACK, null);
                    return;
                }

                session.theirSeqNum = (session.theirSeqNum + packet.payload.length) & 0xFFFFFFFFL;

                try {
                    session.socksOut.write(packet.payload);
                    session.socksOut.flush();
                } catch (IOException e) {
                    sessions.remove(key);
                    closeSession(session);
                    sendRst(packet);
                    return;
                }

                sendTcpPacket(session, Packet.TCP_ACK, null);
            }
        }
    }

    private void connectSocks(String key, TcpSession session) {
        Socket socket = null;
        try {
            socket = new Socket();
            protect(socket);
            socket.connect(new InetSocketAddress(SOCKS_HOST, TorManager.getSocksPort()), 10000);

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            byte[] authResp = new byte[2];
            readFully(in, authResp);
            if (authResp[0] != 0x05 || authResp[1] != 0x00) {
                throw new IOException("SOCKS5 auth negotiation failed");
            }

            byte[] connectReq = new byte[10];
            connectReq[0] = 0x05;
            connectReq[1] = 0x01;
            connectReq[2] = 0x00;
            connectReq[3] = 0x01;
            System.arraycopy(session.remoteAddr, 0, connectReq, 4, 4);
            connectReq[8] = (byte) (session.remotePort >> 8);
            connectReq[9] = (byte) session.remotePort;
            out.write(connectReq);
            out.flush();

            byte[] connectResp = new byte[4];
            readFully(in, connectResp);
            if (connectResp[1] != 0x00) {
                throw new IOException("SOCKS5 connect refused, code: " + connectResp[1]);
            }
            switch (connectResp[3]) {
                case 0x01: skipBytes(in, 6); break;
                case 0x04: skipBytes(in, 18); break;
                case 0x03:
                    int len = in.read();
                    skipBytes(in, len + 2);
                    break;
            }

            socket.setSoTimeout(120000); // 2 min idle timeout prevents zombie threads
            session.socket = socket;
            session.socksIn = in;
            session.socksOut = out;
            session.established = true;

            sendTcpPacket(session, Packet.TCP_SYN | Packet.TCP_ACK, null);
            session.mySeqNum = (session.mySeqNum + 1) & 0xFFFFFFFFL;

            String connDst = addrStr(session.remoteAddr, session.remotePort);
            log("CONNECTED " + connDst + " via Tor");
            trafficLog("TCP → " + connDst + " ✓ connected via Tor");

            session.readerThread = new Thread(() -> socksReaderLoop(key, session), "SOCKS-" + key);
            session.readerThread.start();

        } catch (Exception e) {
            String failDst = addrStr(session.remoteAddr, session.remotePort);
            log("FAILED " + failDst + ": " + e.getMessage());
            trafficLog("TCP → " + failDst + " FAILED: " + e.getMessage());
            sessions.remove(key);
            byte[] rst = Packet.buildTcpPacket(
                session.remoteAddr, session.localAddr,
                session.remotePort, session.localPort,
                session.mySeqNum, session.theirSeqNum,
                Packet.TCP_RST | Packet.TCP_ACK, 0, null);
            writeToVpn(rst);
            if (socket != null && session.socket == null) {
                try { socket.close(); } catch (IOException ignored) {}
            }
            closeSession(session);
        }
    }

    private void socksReaderLoop(String key, TcpSession session) {
        byte[] buffer = new byte[16384];
        long totalBytes = 0;
        try {
            while (running && !session.closed) {
                int read;
                try {
                    read = session.socksIn.read(buffer);
                } catch (java.net.SocketTimeoutException e) {
                    // Idle timeout — close the stale session
                    log("TIMEOUT " + addrStr(session.remoteAddr, session.remotePort));
                    break;
                }
                if (read <= 0) break;

                totalBytes += read;
                int offset = 0;
                while (offset < read) {
                    int chunkSize = Math.min(read - offset, VPN_MTU - 40);
                    byte[] chunk = new byte[chunkSize];
                    System.arraycopy(buffer, offset, chunk, 0, chunkSize);
                    sendTcpPacket(session, Packet.TCP_PSH | Packet.TCP_ACK, chunk);
                    session.mySeqNum = (session.mySeqNum + chunkSize) & 0xFFFFFFFFL;
                    offset += chunkSize;
                }
            }
        } catch (IOException ignored) {}

        if (!session.closed) {
            log("CLOSED " + addrStr(session.remoteAddr, session.remotePort) +
                " (received " + totalBytes + " bytes)");
            sendTcpPacket(session, Packet.TCP_FIN | Packet.TCP_ACK, null);
            session.mySeqNum = (session.mySeqNum + 1) & 0xFFFFFFFFL;
            sessions.remove(key);
            closeSession(session);
        }
    }

    private void sendTcpPacket(TcpSession session, int flags, byte[] data) {
        byte[] pkt = Packet.buildTcpPacket(
            session.remoteAddr, session.localAddr,
            session.remotePort, session.localPort,
            session.mySeqNum, session.theirSeqNum,
            flags, 65535, data);
        writeToVpn(pkt);
    }

    private void sendRst(Packet incoming) {
        byte[] pkt = Packet.buildTcpPacket(
            incoming.dstAddr, incoming.srcAddr,
            incoming.dstPort, incoming.srcPort,
            0, (incoming.seqNum + 1) & 0xFFFFFFFFL,
            Packet.TCP_RST | Packet.TCP_ACK, 0, null);
        writeToVpn(pkt);
    }

    private void handleUdp(Packet packet) {
        if (packet.dstPort == 53 && packet.payload != null && packet.payload.length > 0) {
            String domain = extractDnsName(packet.payload);
            log("DNS query intercepted" + (domain != null ? ": " + domain : ""));
            if (domain != null) trafficLog("DNS → " + domain + " (via Tor)");
            executor.execute(() -> resolveDns(packet));
        }
    }

    private String extractDnsName(byte[] dns) {
        try {
            if (dns.length < 13) return null;
            int pos = 12; // skip header
            StringBuilder name = new StringBuilder();
            while (pos < dns.length) {
                int labelLen = dns[pos] & 0xFF;
                if (labelLen == 0) break;
                if (pos + labelLen >= dns.length) break;
                if (name.length() > 0) name.append('.');
                name.append(new String(dns, pos + 1, labelLen));
                pos += labelLen + 1;
            }
            return name.length() > 0 ? name.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private void resolveDns(Packet packet) {
        Socket socket = null;
        try {
            socket = new Socket();
            protect(socket);
            socket.connect(new InetSocketAddress(SOCKS_HOST, TorManager.getSocksPort()), 5000);
            socket.setSoTimeout(5000);

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            byte[] authResp = new byte[2];
            readFully(in, authResp);
            if (authResp[1] != 0x00) return;

            out.write(new byte[]{
                0x05, 0x01, 0x00, 0x01,
                0x08, 0x08, 0x08, 0x08,
                0x00, 0x35
            });
            out.flush();
            byte[] connectResp = new byte[10];
            readFully(in, connectResp);
            if (connectResp[1] != 0x00) {
                log("DNS: SOCKS5 connect to 8.8.8.8:53 failed");
                return;
            }

            int dnsLen = packet.payload.length;
            out.write(new byte[]{(byte) (dnsLen >> 8), (byte) dnsLen});
            out.write(packet.payload);
            out.flush();

            byte[] lenBuf = new byte[2];
            readFully(in, lenBuf);
            int respLen = ((lenBuf[0] & 0xFF) << 8) | (lenBuf[1] & 0xFF);
            byte[] dnsResponse = new byte[respLen];
            readFully(in, dnsResponse);

            byte[] udpPkt = Packet.buildUdpPacket(
                packet.dstAddr, packet.srcAddr,
                packet.dstPort, packet.srcPort,
                dnsResponse);
            writeToVpn(udpPkt);
            log("DNS resolved (" + respLen + " bytes response)");

        } catch (Exception e) {
            log("DNS failed: " + e.getMessage());
        } finally {
            if (socket != null) try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private synchronized void writeToVpn(byte[] data) {
        try {
            if (vpnOutput != null) vpnOutput.write(data);
        } catch (IOException e) {
            Log.e(TAG, "VPN write failed", e);
        }
    }

    private void closeSession(TcpSession session) {
        session.closed = true;
        try { if (session.socket != null) session.socket.close(); } catch (IOException ignored) {}
        if (session.readerThread != null) session.readerThread.interrupt();
    }

    private static void readFully(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) throw new IOException("Unexpected EOF");
            off += n;
        }
    }

    private static void skipBytes(InputStream in, int count) throws IOException {
        byte[] skip = new byte[count];
        readFully(in, skip);
    }

    private void drainLoop() {
        // Read and discard packets while blocked — prevents buffer filling up
        // VPN fd read() blocks until data arrives, so no busy-waiting
        FileInputStream vpnInput = new FileInputStream(vpnInterface.getFileDescriptor());
        byte[] buffer = new byte[32768];
        while (blocked && !running) {
            try {
                vpnInput.read(buffer);
                // Packets are silently dropped
            } catch (Exception e) {
                if (blocked) {
                    try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                }
            }
        }
    }

    private void updateNotification(String text) {
        String channelId = "tor_vpn";
        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nb = new Notification.Builder(this, channelId);
        } else {
            nb = new Notification.Builder(this);
        }
        Notification notification = nb
            .setContentTitle("Chimæra")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build();
        getSystemService(NotificationManager.class).notify(1, notification);
    }

    private void setupNotification() {
        String channelId = "tor_vpn";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                channelId, "Chimæra", NotificationManager.IMPORTANCE_LOW);
            getSystemService(NotificationManager.class).createNotificationChannel(channel);
        }

        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nb = new Notification.Builder(this, channelId);
        } else {
            nb = new Notification.Builder(this);
        }

        Notification notification = nb
            .setContentTitle("Chimæra")
            .setContentText("Traffic routed through Tor")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build();

        startForeground(1, notification);
    }

    @Override
    public void onDestroy() {
        stop();
        instance = null;
        super.onDestroy();
    }
}
