using NaCl.Core;

namespace Netcode.IO.Internal {
    class Crypto {
        public static byte[] ChaCha20Ploy1305IetfEncrypt(byte[] key, byte[] data, byte[] aad, byte[] nonce) {
            var aede = new ChaCha20Poly1305(key);

            return aede.Encrypt(data, aad, nonce);
        }

        public static byte[] ChaCha20Ploy1305IetfDecrypt( byte[] key, byte[] ciphertext, byte[] aad, byte[] nonce ) {
            var aede = new ChaCha20Poly1305(key);

            return aede.Decrypt(ciphertext, aad, nonce);
        }

        public static byte[] XChaCha20Ploy1305IetfEncrypt( byte[] key, byte[] data, byte[] aad, byte[] nonce ) {
            var aede = new XChaCha20Poly1305(key);

            return aede.Encrypt(data, aad, nonce);
        }

        public static byte[] XChaCha20Ploy1305IetfDecrypt( byte[] key, byte[] ciphertext, byte[] aad, byte[] nonce ) {
            var aede = new XChaCha20Poly1305(key);

            return aede.Decrypt(ciphertext, aad, nonce);
        }
    }
}
