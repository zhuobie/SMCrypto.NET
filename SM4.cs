using System.Runtime.InteropServices;

namespace SMCrypto.NET
{
    public static class SM4
    {
        public static byte[] encrypt_ecb(byte[] input_data, byte[] key)
        {
            IntPtr output_data_len;
            IntPtr ptr = Api.encrypt_ecb(
                input_data,
                new IntPtr(input_data.Length),
                key,
                new IntPtr(key.Length),
                out output_data_len
            );
            try
            {
                byte[] result = new byte[(ulong)output_data_len];
                Marshal.Copy(ptr, result, 0, (int)output_data_len);
                return result;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)output_data_len);
            }
        }

        public static byte[] decrypt_ecb(byte[] input_data, byte[] key)
        {
            IntPtr output_data_len;
            IntPtr ptr = Api.decrypt_ecb(
                input_data,
                new IntPtr(input_data.Length),
                key,
                new IntPtr(key.Length),
                out output_data_len
            );
            try
            {
                byte[] result = new byte[(ulong)output_data_len];
                Marshal.Copy(ptr, result, 0, (int)output_data_len);
                return result;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)output_data_len);
            }
        }

        public static string encrypt_ecb_base64(byte[] input_data, byte[] key)
        {
            IntPtr ptr = Api.encrypt_ecb_base64(
                input_data,
                new IntPtr(input_data.Length),
                key,
                new IntPtr(key.Length)
            );
            try
            {
                string result = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("Failed to convert base64.");
                return result;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }

        public static byte[] decrypt_ecb_base64(string input_data, byte[] key)
        {
            IntPtr output_data_len;
            IntPtr ptr = Api.decrypt_ecb_base64(
                input_data,
                key,
                new IntPtr(key.Length),
                out output_data_len
            );
            try
            {
                byte[] result = new byte[(ulong)output_data_len];
                Marshal.Copy(ptr, result, 0, (int)output_data_len);
                return result;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)output_data_len);
            }
        }

        public static string encrypt_ecb_hex(byte[] input_data, byte[] key)
        {
            IntPtr ptr = Api.encrypt_ecb_hex(
                input_data,
                new IntPtr(input_data.Length),
                key,
                new IntPtr(key.Length)
            );
            try
            {
                string result = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("Failed to convert base64.");
                return result;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }

        public static byte[] decrypt_ecb_hex(string input_data, byte[] key)
        {
            IntPtr output_data_len;
            IntPtr ptr = Api.decrypt_ecb_hex(
                input_data,
                key,
                new IntPtr(key.Length),
                out output_data_len
            );
            try
            {
                byte[] result = new byte[(ulong)output_data_len];
                Marshal.Copy(ptr, result, 0, (int)output_data_len);
                return result;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)output_data_len);
            }
        }

        public static void encrypt_ecb_to_file(string input_file, string output_file, byte[] key)
        {
            try
            {
                Api.encrypt_ecb_to_file(
                    input_file,
                    output_file,
                    key,
                    new IntPtr(key.Length)
                );
            }
            catch (Exception ex)
            {
                throw new Exception("Encrypt ECB to file failed: " + ex.Message);
            }
        }

        public static void decrypt_ecb_from_file(string input_file, string output_file, byte[] key)
        {
            try
            {
                Api.decrypt_ecb_from_file(
                    input_file,
                    output_file,
                    key,
                    new IntPtr(key.Length)
                );
            }
            catch (Exception ex)
            {
                throw new Exception("Decrypt from ECB failed: " + ex.Message);
            }
        }

        public static byte[] encrypt_cbc(byte[] input_data, byte[] key, byte[] iv)
        {
            IntPtr output_data_len;
            IntPtr ptr = Api.encrypt_cbc(
                input_data,
                new IntPtr(input_data.Length),
                key,
                new IntPtr(key.Length),
                iv,
                new IntPtr(iv.Length),
                out output_data_len
            );
            try
            {
                byte[] result = new byte[(ulong)output_data_len];
                Marshal.Copy(ptr, result, 0, (int)output_data_len);
                return result;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)output_data_len);
            }
        }

        public static byte[] decrypt_cbc(byte[] input_data, byte[] key, byte[] iv)
        {
            IntPtr output_data_len;
            IntPtr ptr = Api.decrypt_cbc(
                input_data,
                new IntPtr(input_data.Length),
                key,
                new IntPtr(key.Length),
                iv,
                new IntPtr(iv.Length),
                out output_data_len
            );
            try
            {
                byte[] result = new byte[(ulong)output_data_len];
                Marshal.Copy(ptr, result, 0, (int)output_data_len);
                return result;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)output_data_len);
            }
        }

        public static string encrypt_cbc_base64(byte[] input_data, byte[] key, byte[] iv)
        {
            IntPtr ptr = Api.encrypt_cbc_base64(
                input_data,
                new IntPtr(input_data.Length),
                key,
                new IntPtr(key.Length),
                iv,
                new IntPtr(iv.Length)
            );
            try
            {
                string result = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("Failed to convert base64.");
                return result;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }

        public static byte[] decrypt_cbc_base64(string input_data, byte[] key, byte[] iv)
        {
            IntPtr output_data_len;
            IntPtr ptr = Api.decrypt_cbc_base64(
                input_data,
                key,
                new IntPtr(key.Length),
                iv,
                new IntPtr(iv.Length),
                out output_data_len
            );
            try
            {
                byte[] result = new byte[(ulong)output_data_len];
                Marshal.Copy(ptr, result, 0, (int)output_data_len);
                return result;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)output_data_len);
            }
        }

        public static string encrypt_cbc_hex(byte[] input_data, byte[] key, byte[] iv)
        {
            IntPtr ptr = Api.encrypt_cbc_hex(
                input_data,
                new IntPtr(input_data.Length),
                key,
                new IntPtr(key.Length),
                iv,
                new IntPtr(iv.Length)
            );
            try
            {
                string result = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("Failed to convert base64.");
                return result;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }

        public static byte[] decrypt_cbc_hex(string input_data, byte[] key, byte[] iv)
        {
            IntPtr output_data_len;
            IntPtr ptr = Api.decrypt_cbc_hex(
                input_data,
                key,
                new IntPtr(key.Length),
                iv,
                new IntPtr(iv.Length),
                out output_data_len
            );
            try
            {
                byte[] result = new byte[(ulong)output_data_len];
                Marshal.Copy(ptr, result, 0, (int)output_data_len);
                return result;
            }
            finally
            {
                Api.free_byte_array(ptr, (int)output_data_len);
            }
        }

        public static void encrypt_cbc_to_file(string input_file, string output_file, byte[] key, byte[] iv)
        {
            try
            {
                Api.encrypt_cbc_to_file(
                    input_file,
                    output_file,
                    key,
                    new IntPtr(key.Length),
                    iv,
                    new IntPtr(iv.Length)
                );
            }
            catch (Exception ex)
            {
                throw new Exception("Encrypt CBC to file failed: " + ex.Message);
            }
        }

        public static void decrypt_cbc_from_file(string input_file, string output_file, byte[] key, byte[] iv)
        {
            try
            {
                Api.decrypt_cbc_from_file(
                    input_file,
                    output_file,
                    key,
                    new IntPtr(key.Length),
                    iv,
                    new IntPtr(iv.Length)
                );
            }
            catch (Exception ex)
            {
                throw new Exception("Decrypt from CBC failed: " + ex.Message);
            }
        }


    }
}
