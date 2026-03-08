package com.torproxy;

import java.nio.ByteBuffer;

public class Packet {
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;

    // IP fields
    public int version;
    public int ihl;
    public int totalLength;
    public int protocol;
    public byte[] srcAddr = new byte[4];
    public byte[] dstAddr = new byte[4];

    // TCP/UDP fields
    public int srcPort;
    public int dstPort;
    public long seqNum;
    public long ackNum;
    public int dataOffset;
    public int tcpFlags;
    public int window;
    public byte[] payload;

    public static Packet parse(byte[] data, int length) {
        if (length < 20) return null;

        Packet p = new Packet();
        byte versionIhl = data[0];
        p.version = (versionIhl >> 4) & 0xF;
        p.ihl = versionIhl & 0xF;
        if (p.version != 4) return null;

        p.totalLength = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        p.protocol = data[9] & 0xFF;
        System.arraycopy(data, 12, p.srcAddr, 0, 4);
        System.arraycopy(data, 16, p.dstAddr, 0, 4);

        int ipLen = p.ihl * 4;

        if (p.protocol == PROTO_TCP && length >= ipLen + 20) {
            p.srcPort = ((data[ipLen] & 0xFF) << 8) | (data[ipLen + 1] & 0xFF);
            p.dstPort = ((data[ipLen + 2] & 0xFF) << 8) | (data[ipLen + 3] & 0xFF);
            p.seqNum = ((long)(data[ipLen + 4] & 0xFF) << 24) | ((data[ipLen + 5] & 0xFF) << 16)
                     | ((data[ipLen + 6] & 0xFF) << 8) | (data[ipLen + 7] & 0xFF);
            p.ackNum = ((long)(data[ipLen + 8] & 0xFF) << 24) | ((data[ipLen + 9] & 0xFF) << 16)
                     | ((data[ipLen + 10] & 0xFF) << 8) | (data[ipLen + 11] & 0xFF);
            p.dataOffset = (data[ipLen + 12] >> 4) & 0xF;
            p.tcpFlags = data[ipLen + 13] & 0x3F;
            p.window = ((data[ipLen + 14] & 0xFF) << 8) | (data[ipLen + 15] & 0xFF);

            int tcpLen = p.dataOffset * 4;
            int payloadStart = ipLen + tcpLen;
            int payloadLen = p.totalLength - payloadStart;
            if (payloadLen > 0 && payloadStart < length) {
                p.payload = new byte[Math.min(payloadLen, length - payloadStart)];
                System.arraycopy(data, payloadStart, p.payload, 0, p.payload.length);
            } else {
                p.payload = new byte[0];
            }
        } else if (p.protocol == PROTO_UDP && length >= ipLen + 8) {
            p.srcPort = ((data[ipLen] & 0xFF) << 8) | (data[ipLen + 1] & 0xFF);
            p.dstPort = ((data[ipLen + 2] & 0xFF) << 8) | (data[ipLen + 3] & 0xFF);
            int udpLen = ((data[ipLen + 4] & 0xFF) << 8) | (data[ipLen + 5] & 0xFF);
            int payloadLen = udpLen - 8;
            int payloadStart = ipLen + 8;
            if (payloadLen > 0 && payloadStart < length) {
                p.payload = new byte[Math.min(payloadLen, length - payloadStart)];
                System.arraycopy(data, payloadStart, p.payload, 0, p.payload.length);
            } else {
                p.payload = new byte[0];
            }
        }

        return p;
    }

    public static byte[] buildTcpPacket(byte[] srcAddr, byte[] dstAddr,
            int srcPort, int dstPort, long seqNum, long ackNum,
            int flags, int window, byte[] data) {
        int dataLen = (data != null) ? data.length : 0;
        int totalLen = 40 + dataLen; // 20 IP + 20 TCP + data
        byte[] pkt = new byte[totalLen];

        // IP header
        pkt[0] = 0x45;
        pkt[2] = (byte) (totalLen >> 8);
        pkt[3] = (byte) totalLen;
        pkt[4] = (byte) ((System.nanoTime() >> 8) & 0xFF);
        pkt[5] = (byte) (System.nanoTime() & 0xFF);
        pkt[6] = 0x40; // Don't fragment
        pkt[8] = 64;   // TTL
        pkt[9] = PROTO_TCP;
        System.arraycopy(srcAddr, 0, pkt, 12, 4);
        System.arraycopy(dstAddr, 0, pkt, 16, 4);
        writeChecksum(pkt, 10, computeChecksum(pkt, 0, 20));

        // TCP header
        pkt[20] = (byte) (srcPort >> 8);
        pkt[21] = (byte) srcPort;
        pkt[22] = (byte) (dstPort >> 8);
        pkt[23] = (byte) dstPort;
        pkt[24] = (byte) (seqNum >> 24);
        pkt[25] = (byte) (seqNum >> 16);
        pkt[26] = (byte) (seqNum >> 8);
        pkt[27] = (byte) seqNum;
        pkt[28] = (byte) (ackNum >> 24);
        pkt[29] = (byte) (ackNum >> 16);
        pkt[30] = (byte) (ackNum >> 8);
        pkt[31] = (byte) ackNum;
        pkt[32] = 0x50; // data offset = 5 (20 bytes)
        pkt[33] = (byte) flags;
        pkt[34] = (byte) (window >> 8);
        pkt[35] = (byte) window;

        if (data != null) {
            System.arraycopy(data, 0, pkt, 40, data.length);
        }

        writeChecksum(pkt, 36, computeTransportChecksum(srcAddr, dstAddr, PROTO_TCP, pkt, 20, totalLen - 20));
        return pkt;
    }

    public static byte[] buildUdpPacket(byte[] srcAddr, byte[] dstAddr,
            int srcPort, int dstPort, byte[] data) {
        int dataLen = (data != null) ? data.length : 0;
        int udpLen = 8 + dataLen;
        int totalLen = 20 + udpLen;
        byte[] pkt = new byte[totalLen];

        // IP header
        pkt[0] = 0x45;
        pkt[2] = (byte) (totalLen >> 8);
        pkt[3] = (byte) totalLen;
        pkt[4] = (byte) ((System.nanoTime() >> 8) & 0xFF);
        pkt[5] = (byte) (System.nanoTime() & 0xFF);
        pkt[6] = 0x40;
        pkt[8] = 64;
        pkt[9] = PROTO_UDP;
        System.arraycopy(srcAddr, 0, pkt, 12, 4);
        System.arraycopy(dstAddr, 0, pkt, 16, 4);
        writeChecksum(pkt, 10, computeChecksum(pkt, 0, 20));

        // UDP header
        pkt[20] = (byte) (srcPort >> 8);
        pkt[21] = (byte) srcPort;
        pkt[22] = (byte) (dstPort >> 8);
        pkt[23] = (byte) dstPort;
        pkt[24] = (byte) (udpLen >> 8);
        pkt[25] = (byte) udpLen;

        if (data != null) {
            System.arraycopy(data, 0, pkt, 28, data.length);
        }

        short udpChecksum = computeTransportChecksum(srcAddr, dstAddr, PROTO_UDP, pkt, 20, udpLen);
        if (udpChecksum == 0) udpChecksum = (short) 0xFFFF;
        writeChecksum(pkt, 26, udpChecksum);
        return pkt;
    }

    static short computeChecksum(byte[] data, int offset, int length) {
        int sum = 0;
        for (int i = 0; i < length - 1; i += 2) {
            sum += ((data[offset + i] & 0xFF) << 8) | (data[offset + i + 1] & 0xFF);
        }
        if (length % 2 != 0) {
            sum += (data[offset + length - 1] & 0xFF) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (short) ~sum;
    }

    static short computeTransportChecksum(byte[] srcAddr, byte[] dstAddr,
            int protocol, byte[] data, int offset, int length) {
        int sum = 0;
        // Pseudo-header
        sum += ((srcAddr[0] & 0xFF) << 8) | (srcAddr[1] & 0xFF);
        sum += ((srcAddr[2] & 0xFF) << 8) | (srcAddr[3] & 0xFF);
        sum += ((dstAddr[0] & 0xFF) << 8) | (dstAddr[1] & 0xFF);
        sum += ((dstAddr[2] & 0xFF) << 8) | (dstAddr[3] & 0xFF);
        sum += protocol;
        sum += length;
        // Transport segment
        for (int i = 0; i < length - 1; i += 2) {
            sum += ((data[offset + i] & 0xFF) << 8) | (data[offset + i + 1] & 0xFF);
        }
        if (length % 2 != 0) {
            sum += (data[offset + length - 1] & 0xFF) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (short) ~sum;
    }

    private static void writeChecksum(byte[] data, int offset, short checksum) {
        data[offset] = (byte) (checksum >> 8);
        data[offset + 1] = (byte) checksum;
    }
}
