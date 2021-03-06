import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.ByteToMessageDecoder;
import openrs.Cache;
import openrs.FileStore;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class OS117 {
  private static final BigInteger RSA_EXPONENT = new BigInteger("83417783738053606360795816602207191953304846609474320732476402573404186036614343850219601956066771360994386107416321866148159473079678674374687720403874067122985493106284338371079659182148666792926231395427671452828855023970154106448655638043362091362460709669211465368060966770299219318096643511694237100033");
  private static final BigInteger RSA_MODULUS = new BigInteger("121003791342204940240537304839726709584854797083778631205053253551420764503798013565999160101698716128496880972150143562234438410518435176682025434530958294184215641031116771799085452294014522776026755330783113184826800458685453310933046761189248084972780538551751693199624598021907224405154591177378433674409");

  private static Cache cache;
  private static ByteBuffer checksumTable;
  private static ServerChannel channel;

  public static void main(String[] args) throws Exception {
    cache = new Cache(FileStore.open("cache/"));
    checksumTable = cache.createChecksumTable().encode();
    channel = new ServerChannel();
  }

  private static class Initializer extends ChannelInitializer<SocketChannel> {
    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
      ch.pipeline().addLast("handler", new Handler());
    }
  }

  private static class Handler extends ByteToMessageDecoder {
    private Sequence sequence = Sequence.HANDSHAKE;
    private Stage stage = Stage.HEADER;

    int payloadSize;

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
      switch (sequence) {
        case HANDSHAKE:
          if (in.readableBytes() >= 1) {
            int id = in.readUnsignedByte();
            switch (id) {
              case 14:
                ctx.writeAndFlush(ctx.alloc().buffer(1).writeByte(0), ctx.voidPromise());
                sequence = Sequence.LOGIN;

                break;
              case 15:
                int revision = in.readInt();
                if (revision == 117) {
                  ctx.writeAndFlush(ctx.alloc().buffer(1).writeByte(0), ctx.voidPromise());
                  sequence = Sequence.ONDEMAND;
                } else {
                  ctx.writeAndFlush(ctx.alloc().buffer(1).writeByte(6)).addListener(ChannelFutureListener.CLOSE);
                }

                break;
            }
          }

          break;

        case ONDEMAND:
          if (in.readableBytes() >= 4) {
            int connectionType = in.readUnsignedByte();
            switch (connectionType) {
              case 0:
              case 1:
                int cacheId = in.readUnsignedByte();
                int fileId = in.readUnsignedShort();

                ByteBuf response = ctx.alloc().buffer();

                response.writeByte(cacheId);
                response.writeShort(fileId);

                if (cacheId == 0xFF && fileId == 0xFF) {
                  ByteBuffer checksums = checksumTable.duplicate();

                  response.writeByte(0);
                  response.writeInt(checksums.limit());
                  response.writeBytes(checksums);
                } else {
                  ByteBuffer file = cache.getStore().read(cacheId, fileId);

                  int compression = file.get() & 0xFF;
                  int length = file.getInt();

                  response.writeByte(compression);
                  response.writeInt(length);

                  byte[] payload = new byte[compression != 0 ? length + 4 : length];
                  System.arraycopy(file.array(), 5, payload, 0, payload.length);

                  int offset = 8;
                  for (int byteValue : payload) {
                    if (offset == 512) {
                      response.writeByte(0xFF);
                      offset = 1;
                    }

                    response.writeByte(byteValue);
                    offset++;
                  }
                }

                ctx.writeAndFlush(response, ctx.voidPromise());

                break;
              case 2:
              case 3:
                in.skipBytes(3); // skip padding

                break;
              case 4:
                int encryptionVal = in.readUnsignedByte();
                in.skipBytes(2); // skip padding

                break;
            }
          }

          break;
        case LOGIN:
          switch (stage) {
            case HEADER:
              if (in.readableBytes() >= 3) {
                int connectionType = in.readUnsignedByte();
                payloadSize = in.readUnsignedShort();

                stage = Stage.PAYLOAD;
              }
              break;
            case PAYLOAD:
              if (in.readableBytes() >= payloadSize) {
                int clientRev = in.readInt();
                int rsaBlockSize = in.readUnsignedShort();

                ByteBuf rsaBuffer = crypt(ctx.alloc(), in, rsaBlockSize);

                int rsaHeaderId = rsaBuffer.readUnsignedByte();
                int googleAuthType = rsaBuffer.readUnsignedByte();

                int[] seeds = new int[4];
                for (int i = 0; i < seeds.length; i++) {
                  seeds[i] = rsaBuffer.readInt();
                }

                switch (googleAuthType) {
                  case 0:
                  case 3:
                    /*
                     * The entered google auth code
                     */
                    rsaBuffer.readMedium();
                    rsaBuffer.skipBytes(5);

                    break;
                  case 1:
                    /*
                     * Trust computer for 30 days
                     */
                    rsaBuffer.skipBytes(8);

                    break;
                  case 2:
                    /*
                     * New request, sent every time the user has pressed on the 'login' button to
                     * enter the account details.
                     */
                    rsaBuffer.readInt();
                    rsaBuffer.skipBytes(4);

                    break;
                }

                String password = readCString(rsaBuffer);

                // decrypt xtea block
                decipher(in, in.readerIndex(), in.capacity(), seeds);

                String username = readCString(in);

                int clientFlags = in.readUnsignedByte(); // TODO low memory and??

                int clientWidth = in.readUnsignedShort();
                int clientHeight = in.readUnsignedShort();

                int[] uid = new int[24];
                for (int i = 0; i < uid.length; i++) {
                  uid[i] = in.readUnsignedByte();
                }

                String clientParam = readCString(in);
                int someValue = in.readInt();

                int sysBlockId = in.readUnsignedByte(); // must be 6
                int osId = in.readUnsignedByte();
                boolean bit64 = in.readUnsignedByte() == 1;
                int osVersionId = in.readUnsignedByte();
                int vendorId = in.readUnsignedByte();

                in.skipBytes(4); // unknown bytes, requires more research

                int maxMem = in.readUnsignedShort();
                int amtCpu = in.readUnsignedByte();

                in.readUnsignedMedium(); // padding?
                in.readUnsignedShort(); // padding?

                for (int i = 0; i < 4; i++) {
                  readDoubleEndedCString(in); // TODO
                }

                in.readUnsignedByte(); // TODO
                in.readUnsignedShort(); // TODO

                readDoubleEndedCString(in); // TODO
                readDoubleEndedCString(in); // TODO

                in.readUnsignedByte(); // TODO
                in.readUnsignedByte(); // TODO

                for (int i = 0; i < 3; i++) {
                  in.readInt(); // TODO
                }

                in.readInt(); // TODO
                in.readUnsignedByte(); // TODO; client console argument?

                int[] archives = new int[16];
                for (int i = 0; i < archives.length; i++) {
                  archives[i] = in.readInt();
                }

                // ----- end of login decoding -----

                int ownPlayerIdx = 1;
                int playerCap = (1 << 11);

                int regionX = 50;
                int regionY = 50;
                int tileX = 22;
                int tileY = 22;
                int plane = 0;

                int chunkSize = 8;
                int chunkX = (regionX * chunkSize);
                int chunkY = (regionY * chunkSize);

                int absX = (chunkX * chunkSize) | tileX;
                int absY = (chunkY * chunkSize) | tileY;

                int ownPlayerLocHash = absY | (plane << 28 | absX << 14);

                // map region packet
                ByteBuf regionPkt = ctx.alloc().buffer(256);

                regionPkt.writeByte(chunkX + 128);
                regionPkt.writeByte((chunkX >> 8));

                regionPkt.writeByte((chunkX >> 8));
                regionPkt.writeByte(chunkX + 128);

                Set<Integer> surroundingRegions = new HashSet<>();
                for (int y = (chunkY - 6) / 8; y <= (chunkY + 6) / 8; y++) {
                  for (int x = (chunkX - 6) / 8; x <= (chunkX + 6) / 8; x++) {
                    int id = y << 8 | x;

                    if (!surroundingRegions.contains(id)) {
                      surroundingRegions.add(id);
                    }
                  }
                }

                regionPkt.writeShort(surroundingRegions.size());
                for (int i = 0; i < surroundingRegions.size(); i++) {
                  for (int z = 0; z < 4; z++) {
                    regionPkt.writeInt(0);
                  }
                }

                // player initialization
                PacketStream stream = new PacketStream(ctx.alloc().buffer(4609));
                stream.bitAccess();

                stream.writeBits(30, ownPlayerLocHash);

                for (int i = 1; i < playerCap; i++) {
                  if (i != ownPlayerIdx) {
                    stream.writeBits(18, 0);
                  }
                }

                stream.byteAccess();

                // login response
                ByteBuf response = ctx.alloc().buffer();
                response.writeByte(2); // response code
                response.writeByte(0); // TODO identify
                response.writeInt(0);
                response.writeByte(2); // privilege level
                response.writeByte(0); // flagged
                response.writeShort(ownPlayerIdx); // player index
                response.writeByte(1); // member subscription

                response.writeByte(42); // TODO isaac
                response.writeShort(regionPkt.readableBytes() + stream.buffer.readableBytes());

                response.writeBytes(stream.buffer); // player init
                response.writeBytes(regionPkt); // region change

                // window pane
                response.writeByte(32);
                response.writeByte((165 >> 8));
                response.writeByte(165 + 128);

                response.writeByte(32);
                response.writeByte((548 >> 8));
                response.writeByte(548 + 128);

                ctx.writeAndFlush(response, ctx.voidPromise());
              }

              break;
          }

          break;
      }
    }

    private enum Stage {
      HEADER, PAYLOAD
    }

    private enum Sequence {
      HANDSHAKE, ONDEMAND, LOGIN, GAME
    }
  }

  private static class PacketStream {
    private static final int[] BIT_MASK = new int[32];

    static {
      for (int i = 0; i < BIT_MASK.length; i++) {
        BIT_MASK[i] = ((1 << i) - 1);
      }
    }

    private int bitIndex;
    public final ByteBuf buffer;

    public PacketStream(ByteBuf buffer) {
      this.buffer = buffer;
    }

    public PacketStream bitAccess() {
      bitIndex = buffer.writerIndex() * 8;

      return this;
    }

    public PacketStream writeBits(int amtBits, int value) {
      int bytePos = bitIndex >> 3;
      int bitOffset = 8 - (bitIndex & 7);
      bitIndex += amtBits;

      int requiredSpace = bytePos - buffer.writerIndex() + 1;
      requiredSpace += (amtBits + 7) / 8;
      buffer.ensureWritable(requiredSpace);

      for (; amtBits > bitOffset; bitOffset = 8) {
        int tmp = buffer.getByte(bytePos);
        tmp &= ~BIT_MASK[bitOffset];
        tmp |= (value >> (amtBits-bitOffset)) & BIT_MASK[bitOffset];
        buffer.setByte(bytePos++, tmp);
        amtBits -= bitOffset;
      }
      if (amtBits == bitOffset) {
        int tmp = buffer.getByte(bytePos);
        tmp &= ~BIT_MASK[bitOffset];
        tmp |= value & BIT_MASK[bitOffset];
        buffer.setByte(bytePos, tmp);
      } else {
        int tmp = buffer.getByte(bytePos);
        tmp &= ~(BIT_MASK[amtBits] << (bitOffset - amtBits));
        tmp |= (value & BIT_MASK[amtBits]) << (bitOffset - amtBits);
        buffer.setByte(bytePos, tmp);
      }

      return this;
    }

    public PacketStream byteAccess() {
      buffer.writerIndex((bitIndex + 7) / 8);

      return this;
    }
  }

  private static final int CSTRING_TERMINATOR = 0;
  private static StringBuilder bldr = new StringBuilder();

  private static String readCString(ByteBuf in) {
    bldr.delete(0, bldr.length());
    while (in.isReadable()) {
      int character = in.readUnsignedByte();
      if (character == CSTRING_TERMINATOR) {
        break;
      }

      bldr.append((char) character);
    }

    return bldr.toString();
  }

  private static String readDoubleEndedCString(ByteBuf in) throws Exception {
    int terminatorValue = in.readUnsignedByte();
    if (terminatorValue != CSTRING_TERMINATOR) {
      throw new IOException();
    }

    return readCString(in);
  }

  private static final int GOLDEN_RATIO = 0x9E3779B9;
  private static final int ROUNDS = 32;

  private static void decipher(ByteBuf buffer, int start, int end, int[] key) {
    if (key.length != 4) {
      throw new IllegalArgumentException();
    }

    int numQuads = (end - start) / 8;
    for (int i = 0; i < numQuads; i++) {
      int sum = GOLDEN_RATIO * ROUNDS;
      int v0 = buffer.getInt(start + i * 8);
      int v1 = buffer.getInt(start + i * 8 + 4);
      for (int j = 0; j < ROUNDS; j++) {
        v1 -= (((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + key[(sum >>> 11) & 3]);
        sum -= GOLDEN_RATIO;
        v0 -= (((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + key[sum & 3]);
      }

      buffer.setInt(start + i * 8, v0);
      buffer.setInt(start + i * 8 + 4, v1);
    }
  }

  private static ByteBuf crypt(ByteBufAllocator allocator, ByteBuf inData, int size) {
    byte[] bytes = new byte[size];
    inData.readBytes(bytes);

    BigInteger inInt = new BigInteger(bytes);
    BigInteger outInt = inInt.modPow(RSA_EXPONENT, RSA_MODULUS);

    byte[] outData = outInt.toByteArray();

    ByteBuf out = allocator.buffer(outData.length);
    out.writeBytes(outData);

    return out;
  }

  private static class ServerChannel {
    public volatile Channel channel;

    public ServerChannel() throws Exception {
      ServerBootstrap bootstrap = new ServerBootstrap();

      bootstrap.childHandler(new Initializer());
      bootstrap.group(new NioEventLoopGroup(1));
      bootstrap.channel(NioServerSocketChannel.class);
      bootstrap.localAddress(new InetSocketAddress(43594));
      bootstrap.option(ChannelOption.TCP_NODELAY, true);

      this.channel = bootstrap.bind().sync().channel();
    }
  }
}
