using NetcodeIO.NET.Utils.IO;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace NetcodeIO.NET.Utils
{
	internal struct Datagram
	{
		public byte[] payload;
		public int payloadSize;
		public EndPoint sender;

		public void Release()
		{
			BufferPool.ReturnBuffer(payload);
		}
	}

	internal class DatagramQueue
	{
		protected Queue<Datagram> datagramQueue = new Queue<Datagram>();
		protected Queue<EndPoint> endpointPool = new Queue<EndPoint>();

		private object datagram_mutex = new object();
		private object endpoint_mutex = new object();

		private IPAddress defaultAnyAddress;

		private byte[] receiveBuffer;

		public DatagramQueue(IPAddress defaultAnyAddress)
		{
			this.receiveBuffer = new byte[2048];
			this.defaultAnyAddress = defaultAnyAddress;
		}

		public int Count
		{
			get
			{
				return datagramQueue.Count;
			}
		}

		public void Clear()
		{
			datagramQueue.Clear();
			endpointPool.Clear();
		}

		public void ReadFrom( Socket socket )
		{
			EndPoint sender;

			lock (endpoint_mutex)
			{
				if (endpointPool.Count > 0)
					sender = endpointPool.Dequeue();
				else
					sender = new IPEndPoint(defaultAnyAddress, 0);
			}
			
			int recv = socket.ReceiveFrom(this.receiveBuffer, ref sender);

			if (recv > 0)
			{
				Datagram packet = new Datagram();

				byte[] buffer = BufferPool.GetBuffer(recv);

				using(var writer = ByteArrayReaderWriter.Get(buffer)) {
					writer.WriteBuffer(this.receiveBuffer, recv);
				}

				packet.sender = sender;
				packet.payload = buffer;
				packet.payloadSize = recv;

				lock (datagram_mutex)
					datagramQueue.Enqueue(packet);
			} 
		}

		public void Enqueue(Datagram datagram)
		{
			lock(datagram_mutex)
				datagramQueue.Enqueue(datagram);
		}

		public Datagram Dequeue()
		{
			lock(datagram_mutex)
				return datagramQueue.Dequeue();
		}
	}
}
