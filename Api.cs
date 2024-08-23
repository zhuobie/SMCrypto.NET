using System.Runtime.InteropServices;

namespace SMCrypto.NET
{
    internal class Api
    {
        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sm3_hash(byte[] msg, IntPtr len);        

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sm3_hash_string(string msg_string);

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sm3_hash_file(string file_path);

        [StructLayout(LayoutKind.Sequential)]
        internal struct KeyPair
        {
            internal IntPtr private_key;
            internal IntPtr public_key;
        }

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr gen_keypair();

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pk_from_sk(string private_key);

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int privkey_valid(string private_key);

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pubkey_valid(string public_key);

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr keypair_from_pem_file(string pem_file);

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void keypair_to_pem_file(string private_key, string pem_file);

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pubkey_from_pem_file(string pem_file);

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pubkey_to_pem_file(string public_key, string pem_file);

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sign(
            byte[] id,
            IntPtr id_len,
            byte[] data,
            IntPtr data_len,
            string private_key,
            out IntPtr sig_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int verify(
            byte[] id,
            IntPtr id_len,
            byte[] data,
            IntPtr data_len,
            byte[] sign,
            IntPtr sign_len,
            string public_key
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sign_to_file(
            byte[] id,
            IntPtr id_len,
            byte[] data,
            IntPtr data_len,
            string sign_file,
            string private_key
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int verify_from_file(
            byte[] id,
            IntPtr id_len,
            byte[] data,
            IntPtr data_len,
            string sign_file,
            string public_key
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt(
            byte[] data,
            IntPtr data_len,
            string public_key,
            out IntPtr enc_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt(
            byte[] data,
            IntPtr data_len,
            string private_key,
            out IntPtr dec_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_c1c2c3(
            byte[] data,
            IntPtr data_len,
            string public_key,
            out IntPtr enc_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_c1c2c3(
            byte[] data,
            IntPtr data_len,
            string private_key,
            out IntPtr dec_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_asna1(
            byte[] data,
            IntPtr data_len,
            string public_key,
            out IntPtr enc_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_asna1(
            byte[] data,
            IntPtr data_len,
            string private_key,
            out IntPtr dec_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_hex(
            byte[] data,
            IntPtr data_len,
            string public_key
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_hex(
            string data,
            string private_key,
            out IntPtr dec_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_base64(
            byte[] data,
            IntPtr data_len,
            string public_key
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_base64(
            string data,
            string private_key,
            out IntPtr dec_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void encrypt_to_file(
            byte[] data,
            IntPtr data_len,
            string enc_file,
            string public_key
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_from_file(
            string dec_file,
            string private_key,
            out IntPtr dec_len
        );

        [StructLayout(LayoutKind.Sequential)]
        internal struct KeyExchangeData
        {
            public IntPtr data;
            public IntPtr private_key_r;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct KeyExchangeResult
        {
            internal IntPtr k;
            internal IntPtr s12;
        }

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr keyexchange_1ab(
            IntPtr klen,
            byte[] id,
            IntPtr id_len,
            string private_key,
            out IntPtr data_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr keyexchange_2a(
            byte[] id,
            IntPtr id_len,
            string private_key,
            string private_key_r,
            byte[] recive_bytes,
            IntPtr recive_bytes_len,
            out IntPtr s12_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr keyexchange_2b(
            byte[] id,
            IntPtr id_len,
            string private_key,
            string private_key_r,
            byte[] recive_bytes,
            IntPtr recive_bytes_len,
            out IntPtr s12_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_ecb(
            byte[] input_data,
            IntPtr input_data_len,
            byte[] key,
            IntPtr key_len,
            out IntPtr output_data_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_ecb_base64(
            byte[] input_data,
            IntPtr input_data_len,
            byte[] key,
            IntPtr key_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_ecb_hex(
            byte[] input_data,
            IntPtr input_data_len,
            byte[] key,
            IntPtr key_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void encrypt_ecb_to_file(
            string input_file,
            string output_file,
            byte[] key,
            IntPtr key_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_ecb(
            byte[] input_data,
            IntPtr input_data_len,
            byte[] key,
            IntPtr key_len,
            out IntPtr output_data_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_ecb_base64(
            string input_data,
            byte[] key,
            IntPtr key_len,
            out IntPtr output_data_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_ecb_hex(
            string input_data,
            byte[] key,
            IntPtr key_len,
            out IntPtr output_data_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void decrypt_ecb_from_file(
            string input_file,
            string output_file,
            byte[] key,
            IntPtr key_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_cbc(
            byte[] input_data,
            IntPtr input_data_len,
            byte[] key,
            IntPtr key_len,
            byte[] iv,
            IntPtr iv_len,
            out IntPtr output_data_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_cbc_base64(
            byte[] input_data,
            IntPtr input_data_len,
            byte[] key,
            IntPtr key_len,
            byte[] iv,
            IntPtr iv_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr encrypt_cbc_hex(
            byte[] input_data,
            IntPtr input_data_len,
            byte[] key,
            IntPtr key_len,
            byte[] iv,
            IntPtr iv_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void encrypt_cbc_to_file(
            string input_file,
            string output_file,
            byte[] key,
            IntPtr key_len,
            byte[] iv,
            IntPtr iv_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_cbc(
            byte[] input_data,
            IntPtr input_data_len,
            byte[] key,
            IntPtr key_len,
            byte[] iv,
            IntPtr iv_len,
            out IntPtr output_data_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_cbc_base64(
            string input_data,
            byte[] key,
            IntPtr key_len,
            byte[] iv,
            IntPtr iv_len,
            out IntPtr output_data_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr decrypt_cbc_hex(
            string input_data,
            byte[] key,
            IntPtr key_len,
            byte[] iv,
            IntPtr iv_len,
            out IntPtr output_data_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void decrypt_cbc_from_file(
            string input_file,
            string output_file,
            byte[] key,
            IntPtr key_len,
            byte[] iv,
            IntPtr iv_len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void free_char_array(IntPtr ptr);

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void free_byte_array(
            IntPtr ptr,
            IntPtr len
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void free_struct_keypair(
            IntPtr ptr
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void free_struct_keyexchangedata(
            IntPtr ptr
        );

        [DllImport("smcrypto_ffi", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void free_struct_keyexchangeresult(
            IntPtr ptr
        );
    }
}
