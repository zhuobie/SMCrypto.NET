using System.Runtime.InteropServices;

namespace SMCrypto.NET
{
    public static class SM2
    {
        public static (string, string) gen_keypair()
        {
            IntPtr ptr = Api.gen_keypair();
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("Keypair generation failed. Returned null pointer.");
            }
            try
            {
                Api.KeyPair keyPair = Marshal.PtrToStructure<Api.KeyPair>(ptr);
                string private_key = Marshal.PtrToStringAnsi(keyPair.private_key) ?? throw new Exception("Failed to convert private key.");
                string public_key = Marshal.PtrToStringAnsi(keyPair.public_key) ?? throw new Exception("Failed to convert public key.");
                return (private_key, public_key);
            }
            finally
            {
                Api.free_struct_keypair(ptr);
            }
        }

        public static string pk_from_sk(string private_key)
        {
            IntPtr ptr = Api.pk_from_sk(private_key);
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("SM3 hash failed. Returned null pointer.");
            }
            try
            {
                string public_key = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("Failed to export public key.");
                return public_key;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }

        public static int privkey_valid(string private_key)
        {
            return Api.privkey_valid(private_key);
        }

        public static int pubkey_valid(string public_key)
        {
            return Api.pubkey_valid(public_key);
        }

        public static (string, string) keypair_from_pem_file(string pem_file)
        {
            IntPtr ptr = Api.keypair_from_pem_file(pem_file);
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("Keypair load failed. Returned null pointer.");
            }
            try
            {
                Api.KeyPair keyPair = Marshal.PtrToStructure<Api.KeyPair>(ptr);
                string private_key = Marshal.PtrToStringAnsi(keyPair.private_key) ?? throw new Exception("Failed to convert private key.");
                string public_key = Marshal.PtrToStringAnsi(keyPair.public_key) ?? throw new Exception("Failed to convert public key.");
                return (private_key, public_key);
            }
            finally
            {
                Api.free_struct_keypair(ptr);
            }
        }

        public static void keypair_to_pem_file(string private_key, string pem_file)
        {
            try
            {
                Api.keypair_to_pem_file(private_key, pem_file);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to save keypair to pem file: " + ex.Message);
            }
        }

        public static void pubkey_to_pem_file(string public_key, string pem_file)
        {
            try
            {
                Api.pubkey_to_pem_file(public_key, pem_file);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to save public key to pem file: " + ex.Message);
            }
        }

        public static byte[] sign(byte[] id, byte[] data, string private_key)
        {
            IntPtr sig_len;
            IntPtr ptr = Api.sign(
                id,
                new IntPtr(id.Length),
                data,
                new IntPtr(data.Length),
                private_key,
                out sig_len
            );
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("Failed to sign data. Returned null pointer.");
            }
            try
            {
                byte[] sig = new byte[(ulong)sig_len];
                Marshal.Copy(ptr, sig, 0, (int)sig_len);
                return sig;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)sig_len);
            }
        }

        public static int verify(byte[] id, byte[] data, byte[] sign, string public_key)
        {
            IntPtr ptr = Api.verify(
                id,
                new IntPtr(id.Length),
                data,
                new IntPtr(data.Length),
                sign,
                new IntPtr(sign.Length),
                public_key
            );
            int verify = (int)ptr;
            return verify;
        }

        public static void sign_to_file(byte[] id, byte[] data, string sign_file, string private_key)
        {
            try
            {
                Api.sign_to_file(
                    id,
                    new IntPtr(id.Length),
                    data,
                    new IntPtr(data.Length),
                    sign_file,
                    private_key
                );
            }
            catch (Exception ex)
            {
                throw new Exception("Sign to file failed: " + ex.Message);
            }
        }

        public static int verify_from_file(byte[] id, byte[] data, string sign_file, string public_key)
        {
            IntPtr ptr = Api.verify_from_file(
                id,
                new IntPtr(id.Length),
                data,
                new IntPtr(data.Length),
                sign_file,
                public_key
            );
            int verify = (int)ptr;
            return verify;
        }

        public static byte[] encrypt(byte[] data, string public_key)
        {
            IntPtr enc_len;
            IntPtr ptr = Api.encrypt(
                data,
                new IntPtr(data.Length),
                public_key,
                out enc_len
            );
            try
            {
                byte[] enc = new byte[(ulong)enc_len];
                Marshal.Copy(ptr, enc, 0, (int)enc_len);
                return enc;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)enc_len);
            }
        }

        public static byte[] decrypt(byte[] data, string private_key)
        {
            IntPtr dec_len;
            IntPtr ptr = Api.decrypt(
                data,
                new IntPtr(data.Length),
                private_key,
                out dec_len
            );
            try
            {
                byte[] dec = new byte[(ulong)dec_len];
                Marshal.Copy(ptr, dec, 0, (int)dec_len);
                return dec;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)dec_len);
            }
        }

        public static byte[] encrypt_c1c2c3(byte[] data, string public_key)
        {
            IntPtr enc_len;
            IntPtr ptr = Api.encrypt_c1c2c3(
                data,
                new IntPtr(data.Length),
                public_key,
                out enc_len
            );
            try
            {
                byte[] enc = new byte[(ulong)enc_len];
                Marshal.Copy(ptr, enc, 0, (int)enc_len);
                return enc;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)enc_len);
            }
        }

        public static byte[] decrypt_c1c2c3(byte[] data, string private_key)
        {
            IntPtr dec_len;
            IntPtr ptr = Api.decrypt_c1c2c3(
                data,
                new IntPtr(data.Length),
                private_key,
                out dec_len
            );
            try
            {
                byte[] dec = new byte[(ulong)dec_len];
                Marshal.Copy(ptr, dec, 0, (int)dec_len);
                return dec;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)dec_len);
            }
        }

        public static byte[] encrypt_asna1(byte[] data, string public_key)
        {
            IntPtr enc_len;
            IntPtr ptr = Api.encrypt_asna1(
                data,
                new IntPtr(data.Length),
                public_key,
                out enc_len
            );
            try
            {
                byte[] enc = new byte[(ulong)enc_len];
                Marshal.Copy(ptr, enc, 0, (int)enc_len);
                return enc;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)enc_len);
            }
        }

        public static byte[] decrypt_asna1(byte[] data, string private_key)
        {
            IntPtr dec_len;
            IntPtr ptr = Api.decrypt_asna1(
                data,
                new IntPtr(data.Length),
                private_key,
                out dec_len
            );
            try
            {
                byte[] dec = new byte[(ulong)dec_len];
                Marshal.Copy(ptr, dec, 0, (int)dec_len);
                return dec;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)dec_len);
            }
        }
        
        public static string encrypt_hex(byte[] data, string public_key)
        {
            IntPtr ptr = Api.encrypt_hex(
                data,
                new IntPtr(data.Length),
                public_key
            );
            try{
                string enc = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("Encrypt failed. Returned null pointer.");
                return enc;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }

        public static byte[] decrypt_hex(string data, string private_key)
        {
            IntPtr dec_len;
            IntPtr ptr = Api.decrypt_hex(
                data,
                private_key,
                out dec_len
            );
            try
            {
                byte[] dec = new byte[(ulong)dec_len];
                Marshal.Copy(ptr, dec, 0, (int)dec_len);
                return dec;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)dec_len);
            }
        }

        public static string encrypt_base64(byte[] data, string public_key)
        {
            IntPtr ptr = Api.encrypt_base64(
                data,
                new IntPtr(data.Length),
                public_key
            );
            try{
                string enc = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("Encrypt failed. Returned null pointer.");
                return enc;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }

        public static byte[] decrypt_base64(string data, string private_key)
        {
            IntPtr dec_len;
            IntPtr ptr = Api.decrypt_base64(
                data,
                private_key,
                out dec_len
            );
            try
            {
                byte[] dec = new byte[(ulong)dec_len];
                Marshal.Copy(ptr, dec, 0, (int)dec_len);
                return dec;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)dec_len);
            }
        }

        public static void encrypt_to_file(byte[] data, string enc_file, string public_key)
        {
            try
            {
                Api.encrypt_to_file(
                    data,
                    new IntPtr(data.Length),
                    enc_file,
                    public_key
                );
            }
            catch (Exception ex)
            {
                throw new Exception("Encrypt to file failed: " + ex.Message);
            }
        }

        public static byte[] decrypt_from_file(string dec_file, string private_key)
        {
            IntPtr dec_len;
            IntPtr ptr = Api.decrypt_from_file(
                dec_file,
                private_key,
                out dec_len
            );
            try
            {
                byte[] dec = new byte[(ulong)dec_len];
                Marshal.Copy(ptr, dec, 0, (int)dec_len);
                return dec;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)dec_len);
            }
        }

        public static (byte[], string) keyexchange_1ab(int klen, byte[] id, string private_key)
        {
            IntPtr data_len;
            IntPtr ptr = Api.keyexchange_1ab(
                new IntPtr(klen),
                id,
                new IntPtr(id.Length),
                private_key,
                out data_len
            );
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("Keyexchange step one failed. Returned null pointer.");
            }
            try
            {
                Api.KeyExchangeData keyExchangeData = Marshal.PtrToStructure<Api.KeyExchangeData>(ptr);
                byte[] data = new byte[(ulong)data_len];
                Marshal.Copy(keyExchangeData.data, data, 0, (int)data_len);
                string private_key_r = Marshal.PtrToStringAnsi(keyExchangeData.private_key_r) ?? throw new Exception("Failed to convert private key r.");
                return (data, private_key_r);
            }
            finally
            {
                Api.free_struct_keyexchangedata(ptr);
            }
        }

        public static (string, byte[]) keyexchange_2a(byte[] id, string private_key, string private_key_r, byte[] recive_bytes)
        {
            IntPtr s12_len;
            IntPtr ptr = Api.keyexchange_2a(
                id,
                new IntPtr(id.Length),
                private_key,
                private_key_r,
                recive_bytes,
                new IntPtr(recive_bytes.Length),
                out s12_len
            );
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("Keyexchange step two failed. Returned null pointer.");
            }
            try
            {
                Api.KeyExchangeResult keyExchangeResult = Marshal.PtrToStructure<Api.KeyExchangeResult>(ptr);
                string k = Marshal.PtrToStringAnsi(keyExchangeResult.k) ?? throw new Exception("Failed to convert k.");
                byte[] s12 = new byte[(ulong)s12_len];
                Marshal.Copy(keyExchangeResult.s12, s12, 0, (int)s12_len);
                return (k, s12);
            }
            finally
            {
                Api.free_struct_keyexchangeresult(ptr);
            }
        }

        public static (string, byte[]) keyexchange_2b(byte[] id, string private_key, string private_key_r, byte[] recive_bytes)
        {
            IntPtr s12_len;
            IntPtr ptr = Api.keyexchange_2b(
                id,
                new IntPtr(id.Length),
                private_key,
                private_key_r,
                recive_bytes,
                new IntPtr(recive_bytes.Length),
                out s12_len
            );
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("Keyexchange step two failed. Returned null pointer.");
            }
            try
            {
                Api.KeyExchangeResult keyExchangeResult = Marshal.PtrToStructure<Api.KeyExchangeResult>(ptr);
                string k = Marshal.PtrToStringAnsi(keyExchangeResult.k) ?? throw new Exception("Failed to convert k.");
                byte[] s12 = new byte[(ulong)s12_len];
                Marshal.Copy(keyExchangeResult.s12, s12, 0, (int)s12_len);
                return (k, s12);
            }
            finally
            {
                Api.free_struct_keyexchangeresult(ptr);
            }
        }
    }
}
