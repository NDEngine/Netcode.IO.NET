using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetcodeIO.NET.Utils
{
	/// <summary>
	/// Helper methods for allocating temporary buffers
	/// </summary>
	public static class BufferPool
	{
		private static Dictionary<int, Queue<byte[]>> bufferPool = new Dictionary<int, Queue<byte[]>>();

		//private static int refCount = 0;

		/// <summary>
		/// Retrieve a buffer of the given size
		/// </summary>
		public static byte[] GetBuffer(int size)
		{
			//refCount += 1;

			lock (bufferPool)
			{
				if (bufferPool.ContainsKey(size))
				{
					if (bufferPool[size].Count > 0) {
						//Console.WriteLine($"Give {size} bytes, buffer size { bufferPool[size].Count - 1 }, refcount : {refCount}");

						return bufferPool[size].Dequeue();
					}
				}
			}

			//int bufferSize = bufferPool.ContainsKey(size) ? bufferPool[size].Count : 0;
			//Console.WriteLine($"Alloc {size} bytes, buffer size { bufferSize } refcount : {refCount}");

			return new byte[size];
		}

		/// <summary>
		/// Return a buffer to the pool
		/// </summary>
		public static void ReturnBuffer(byte[] buffer)
		{
			//refCount -= 1;

			lock (bufferPool)
			{
				if (!bufferPool.ContainsKey(buffer.Length))
					bufferPool.Add(buffer.Length, new Queue<byte[]>());

				System.Array.Clear(buffer, 0, buffer.Length);
				bufferPool[buffer.Length].Enqueue(buffer);

				//Console.WriteLine($"Release {buffer.Length} bytes, buffer size { bufferPool[buffer.Length].Count }, refcount : {refCount}");
			}
		}
	}
}
