using System;
using Netcode.IO.Internal;
using NetcodeIO.NET.Utils;
using NetcodeIO.NET.Utils.IO;

namespace NetcodeIO.NET.Internal
{
	/// <summary>
	/// Helper class for reading/writing packets
	/// </summary>
	internal static class PacketIO
	{
		/// <summary>
		/// Read and decrypt packet data into an output buffer
		/// </summary>
		public static int ReadPacketData(NetcodePacketHeader header, ByteArrayReaderWriter stream, int length, ulong protocolID, byte[] key, byte[] outputBuffer)
		{
			byte[] encryptedBuffer = BufferPool.GetBuffer(2048);
			stream.ReadBytesIntoBuffer(encryptedBuffer, length);
			
			int decryptedBytes;
			try
			{
				decryptedBytes = DecryptPacketData(header, protocolID, encryptedBuffer, length, key, outputBuffer);
			}
			catch(Exception e)
			{
				BufferPool.ReturnBuffer(encryptedBuffer);
				throw e;
			}

            BufferPool.ReturnBuffer(encryptedBuffer);
			return decryptedBytes;
		}

		/// <summary>
		/// Encrypt a packet's data
		/// </summary>
		public static int EncryptPacketData(NetcodePacketHeader header, ulong protocolID, byte[] packetData, int packetDataLen, byte[] key, byte[] outBuffer)
		{
			byte[] additionalData = BufferPool.GetBuffer(Defines.NETCODE_VERSION_INFO_BYTES + 8 + 1);
			using (var writer = ByteArrayReaderWriter.Get(additionalData))
			{
				writer.WriteASCII(Defines.NETCODE_VERSION_INFO_STR);
				writer.Write(protocolID);
				writer.Write(header.GetPrefixByte());
			}

			byte[] nonce = BufferPool.GetBuffer(12);
			using (var writer = ByteArrayReaderWriter.Get(nonce))
			{
				writer.Write((UInt32)0);
				writer.Write(header.SequenceNumber);
			}

            byte[] data = BufferPool.GetBuffer(packetDataLen);

            int ret;

			try {
                BufferPool.ReturnBuffer(data);

                using (var reader = ByteArrayReaderWriter.Get(packetData)) {
                    reader.ReadBytesIntoBuffer(data, packetDataLen);
                }

                var buffer = Crypto.ChaCha20Ploy1305IetfEncrypt(key, data, additionalData, nonce);

                using (var writer = ByteArrayReaderWriter.Get(outBuffer)) {
                    writer.WriteBuffer(buffer, buffer.Length);
                }

                ret = buffer.Length;

                BufferPool.ReturnBuffer(data);
			}
			catch (Exception e)
			{
				BufferPool.ReturnBuffer(additionalData);
				BufferPool.ReturnBuffer(nonce);
                BufferPool.ReturnBuffer(data);

				throw e;
			}

			BufferPool.ReturnBuffer(additionalData);
			BufferPool.ReturnBuffer(nonce);

			return ret;
		}

		/// <summary>
		/// Decrypt a packet's data
		/// </summary>
		public static int DecryptPacketData(NetcodePacketHeader header, ulong protocolID, byte[] packetData, int packetDataLen, byte[] key, byte[] outBuffer)
		{
			byte[] additionalData = BufferPool.GetBuffer(Defines.NETCODE_VERSION_INFO_BYTES + 8 + 1);
			using (var writer = ByteArrayReaderWriter.Get(additionalData))
			{
				writer.WriteASCII(Defines.NETCODE_VERSION_INFO_STR);
				writer.Write(protocolID);
				writer.Write(header.ReadSequenceByte);
			}

			byte[] nonce = BufferPool.GetBuffer(12);
			using (var writer = ByteArrayReaderWriter.Get(nonce))
			{
				writer.Write((UInt32)0);
				writer.Write(header.SequenceNumber);
			}

            byte[] ciphertext = BufferPool.GetBuffer(packetDataLen);

			int ret;
			try {

                using (var reader = ByteArrayReaderWriter.Get(packetData)) {
                    reader.ReadBytesIntoBuffer(ciphertext, packetDataLen);
                }

				var buffer = Crypto.ChaCha20Ploy1305IetfDecrypt(key, ciphertext, additionalData, nonce);

				using (var writer = ByteArrayReaderWriter.Get(outBuffer)) {
					writer.WriteBuffer(buffer, buffer.Length);
				}

                ret = buffer.Length;

                BufferPool.ReturnBuffer(ciphertext);
            }
			catch(Exception e)
			{
				BufferPool.ReturnBuffer(additionalData);
				BufferPool.ReturnBuffer(nonce);
                BufferPool.ReturnBuffer(ciphertext);

				throw e;
			}

			BufferPool.ReturnBuffer(additionalData);
			BufferPool.ReturnBuffer(nonce);

			return ret;
		}

		/// <summary>
		/// Encrypt a challenge token
		/// </summary>
		public static int EncryptChallengeToken(ulong sequenceNum, byte[] packetData, byte[] key, byte[] outBuffer)
		{
			byte[] additionalData = BufferPool.GetBuffer(0);

			byte[] nonce = BufferPool.GetBuffer(12);
			using (var writer = ByteArrayReaderWriter.Get(nonce))
			{
				writer.Write((UInt32)0);
				writer.Write(sequenceNum);
			}

            byte[] data = BufferPool.GetBuffer(300 - Defines.MAC_SIZE);

            int ret;

            try {
                BufferPool.ReturnBuffer(data);

                using (var reader = ByteArrayReaderWriter.Get(packetData)) {
                    reader.ReadBytesIntoBuffer(data, 300 - Defines.MAC_SIZE);
                }

                var buffer = Crypto.ChaCha20Ploy1305IetfEncrypt(key, data, additionalData, nonce);

                using (var writer = ByteArrayReaderWriter.Get(outBuffer)) {
                    writer.WriteBuffer(buffer, buffer.Length);
                }

                ret = buffer.Length;

                BufferPool.ReturnBuffer(data);
            } catch (Exception e) {
                BufferPool.ReturnBuffer(additionalData);
                BufferPool.ReturnBuffer(nonce);
                BufferPool.ReturnBuffer(data);

                throw e;
            }

			BufferPool.ReturnBuffer(additionalData);
			BufferPool.ReturnBuffer(nonce);

			return ret;
		}

		/// <summary>
		/// Decrypt a challenge token
		/// </summary>
		public static int DecryptChallengeToken(ulong sequenceNum, byte[] packetData, byte[] key, byte[] outBuffer)
		{
			byte[] additionalData = BufferPool.GetBuffer(0);

			byte[] nonce = BufferPool.GetBuffer(12);
			using (var writer = ByteArrayReaderWriter.Get(nonce))
			{
				writer.Write((UInt32)0);
				writer.Write(sequenceNum);
			}

			try {
                var buffer = Crypto.ChaCha20Ploy1305IetfDecrypt(key, packetData, additionalData, nonce);

                using (var writer = ByteArrayReaderWriter.Get(outBuffer)) {
                    writer.WriteBuffer(buffer, 300 - Defines.MAC_SIZE);
                }
            }
			catch (Exception e)
			{
				BufferPool.ReturnBuffer(additionalData);
				BufferPool.ReturnBuffer(nonce);
				throw e;
			}

			BufferPool.ReturnBuffer(additionalData);
			BufferPool.ReturnBuffer(nonce);

			return 300 - Defines.MAC_SIZE;
		}

		// Encrypt a private connect token
		public static int EncryptPrivateConnectToken(byte[] privateConnectToken, ulong protocolID, ulong expireTimestamp, ulong sequence, byte[] key, byte[] outBuffer)
		{
			int len = privateConnectToken.Length;

			byte[] additionalData = BufferPool.GetBuffer(Defines.NETCODE_VERSION_INFO_BYTES + 8 + 8);
			using (var writer = ByteArrayReaderWriter.Get(additionalData))
			{
				writer.WriteASCII(Defines.NETCODE_VERSION_INFO_STR);
				writer.Write(protocolID);
				writer.Write(expireTimestamp);
			}

			byte[] nonce = BufferPool.GetBuffer(12);
			using (var writer = ByteArrayReaderWriter.Get(nonce))
			{
				writer.Write((UInt32)0);
				writer.Write(sequence);
			}

            byte[] data = BufferPool.GetBuffer(len - Defines.MAC_SIZE);

            int ret;

            try {
                BufferPool.ReturnBuffer(data);

                using (var reader = ByteArrayReaderWriter.Get(privateConnectToken)) {
                    reader.ReadBytesIntoBuffer(data, len - Defines.MAC_SIZE);
                }

                var buffer = Crypto.ChaCha20Ploy1305IetfEncrypt(key, data, additionalData, nonce);

                using (var writer = ByteArrayReaderWriter.Get(outBuffer)) {
                    writer.WriteBuffer(buffer, buffer.Length);
                }

                ret = buffer.Length;

                BufferPool.ReturnBuffer(data);
            } catch (Exception e) {
                BufferPool.ReturnBuffer(additionalData);
                BufferPool.ReturnBuffer(nonce);
                BufferPool.ReturnBuffer(data);

                throw e;
            }

			BufferPool.ReturnBuffer(additionalData);
			BufferPool.ReturnBuffer(nonce);

			return ret;
		}

		// Decrypt a private connect token
		public static int DecryptPrivateConnectToken(byte[] encryptedConnectToken, ulong protocolID, ulong expireTimestamp, byte[] nonce, byte[] key, byte[] outBuffer)
		{
			int len = encryptedConnectToken.Length;

			byte[] additionalData = BufferPool.GetBuffer(Defines.NETCODE_VERSION_INFO_BYTES + 8 + 8);
			using (var writer = ByteArrayReaderWriter.Get(additionalData))
			{
				writer.WriteASCII(Defines.NETCODE_VERSION_INFO_STR);
				writer.Write(protocolID);
				writer.Write(expireTimestamp);
			}

			byte[] nonceBuffer = BufferPool.GetBuffer(Defines.NETCODE_CONNECT_TOKEN_NONCE_BYTES);
			using (var writer = ByteArrayReaderWriter.Get(nonceBuffer))
			{
				writer.WriteBuffer(nonce, Defines.NETCODE_CONNECT_TOKEN_NONCE_BYTES);
				//writer.Write((UInt32)0);
				//writer.Write(sequence);
			}

            try {
                var buffer = Crypto.XChaCha20Ploy1305IetfDecrypt(key, encryptedConnectToken, additionalData, nonceBuffer);

                using (var writer = ByteArrayReaderWriter.Get(outBuffer)) {
                    writer.WriteBuffer(buffer, len - Defines.MAC_SIZE);
                }

            } catch {
                BufferPool.ReturnBuffer(additionalData);
                BufferPool.ReturnBuffer(nonce);

                throw;
            }

			BufferPool.ReturnBuffer(additionalData);
			BufferPool.ReturnBuffer(nonce);

			return len - Defines.MAC_SIZE;
		}
	}
}
