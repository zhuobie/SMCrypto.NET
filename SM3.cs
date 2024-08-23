using System.Runtime.InteropServices;

namespace SMCrypto.NET
{
    public static class SM3
    {
        public static string sm3_hash(byte[] msg) {
            IntPtr ptr = Api.sm3_hash(msg, new IntPtr(msg.Length));
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("SM3 hash failed. Returned null pointer.");
            }
            try
            {
                string? hash = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("SM3 hash failed. Failed to convert unmanaged string to managed string.");
                return hash;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }

        public static string sm3_hash_string(string msg_str)
        {
            IntPtr ptr = Api.sm3_hash_string(msg_str);
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("SM3 hash failed. Returned null pointer.");
            }
            try
            {
                string? hash = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("SM3 hash failed. Failed to convert unmanaged string to managed string.");
                return hash;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }

        public static string sm3_hash_file(string file_path)
        {
            IntPtr ptr = Api.sm3_hash_file(file_path);
            if (ptr == IntPtr.Zero)
            {
                throw new Exception("SM3 hash failed. Returned null pointer.");
            }
            try
            {
                string? hash = Marshal.PtrToStringAnsi(ptr) ?? throw new Exception("SM3 hash failed. Failed to convert unmanaged string to managed string.");
                return hash;
            }
            finally
            {
                Api.free_char_array(ptr);
            }
        }


    }   

}
