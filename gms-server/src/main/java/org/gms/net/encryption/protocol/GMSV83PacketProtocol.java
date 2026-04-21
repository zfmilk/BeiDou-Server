package org.gms.net.encryption.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.SocketChannel;
import org.gms.client.Client;
import org.gms.constants.net.ServerConstants;
import org.gms.net.encryption.ClientCyphers;
import org.gms.net.encryption.InitializationVector;
import org.gms.net.encryption.MapleAESOFB;
import org.gms.net.encryption.MapleCustomEncryption;
import org.gms.net.netty.InvalidPacketHeaderException;
import org.gms.net.packet.ByteBufInPacket;
import org.gms.net.packet.Packet;
import org.gms.util.PacketCreator;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GMSV83PacketProtocol implements PacketProtocol {
    private static final Logger log = LoggerFactory.getLogger(GMSV83PacketProtocol.class);
    private final MapleAESOFB receiveCypher;
    private final MapleAESOFB sendCypher;

    public GMSV83PacketProtocol(ClientCyphers clientCyphers) {
        this.receiveCypher = clientCyphers.getReceiveCypher();
        this.sendCypher = clientCyphers.getSendCypher();
    }

    @Override
    public void decode(ChannelHandlerContext context, ByteBuf in, List<Object> out) {
        final int header = in.readInt();
        log.info("=== DECODE DEBUG === header: {}, isValid: {}, IV: {}", Integer.toHexString(header), receiveCypher.isValidHeader(header), receiveCypher);

        if (!receiveCypher.isValidHeader(header)) {
            throw new InvalidPacketHeaderException("Attempted to decode a packet with an invalid header", header);
        }

        final int packetLength = decodePacketLength(header);
        byte[] packet = new byte[packetLength];
        in.readBytes(packet);
        log.info("=== DECODE DEBUG === Raw packet bytes ({}): {}", packet.length, org.gms.util.HexTool.toHexString(packet));
        receiveCypher.crypt(packet);
        log.info("=== DECODE DEBUG === After AES crypt: {}", org.gms.util.HexTool.toHexString(packet));
        MapleCustomEncryption.decryptData(packet);
        log.info("=== DECODE DEBUG === After MapleCustom decrypt: {}", org.gms.util.HexTool.toHexString(packet));
        out.add(new ByteBufInPacket(Unpooled.wrappedBuffer(packet)));
    }

    /**
     * @param header Packet header - the first 4 bytes of the packet
     * @return Packet size in bytes
     */
    private static int decodePacketLength(byte[] header) {
        return (((header[1] ^ header[3]) & 0xFF) << 8) | ((header[0] ^ header[2]) & 0xFF);
    }

    private int decodePacketLength(int header) {
        int length = ((header >>> 16) ^ (header & 0xFFFF));
        length = ((length << 8) & 0xFF00) | ((length >>> 8) & 0xFF);
        return length;
    }

    @Override
    public void encode(ChannelHandlerContext ctx, Packet in, ByteBuf out) {
        byte[] packet = in.getBytes();
        out.writeBytes(getEncodedHeader(packet.length));

        MapleCustomEncryption.encryptData(packet);
        sendCypher.crypt(packet);
        out.writeBytes(packet);
    }

    private byte[] getEncodedHeader(int length) {
        return sendCypher.getPacketHeader(length);
    }

    @Override
    public void writeInitialUnencryptedHelloPacket(SocketChannel socketChannel, InitializationVector sendIv, InitializationVector recvIv, Client client) {
        socketChannel.writeAndFlush(Unpooled.wrappedBuffer(PacketCreator.getHello(ServerConstants.VERSION, sendIv, recvIv).getBytes()));
    }
}
