using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Mono.Options;
namespace Aesx
{

	public class Aesx
	{
		static void Main(string[] args)
		{
			try
			{

			//	string original = "This is original text";
				//string output = null;
				string  input = null;
				string  key = null;
				string  choose = null;
				string  output = null;
				var show_help = false;
				var p = new OptionSet () {
					{ "i=", "The input file",   v => input = v },
					{"k=", "The key",   v => key = v  },
					{"o=", "The output",   v => output = v  },
					{"c=", "The output",   v => choose = v  },
	
					"other:",
					{ "h|help",  "show this message", 
						v => show_help = v != null },
				};

				try {
					p.Parse (args);
				}
				catch (OptionException e)
				{
					Console.WriteLine (e.Message);
					return;
				}

				if (show_help) {
					p.WriteOptionDescriptions (Console.Out);
					return;
				}

				if (input == null)
				{
					Console.WriteLine("Введите корректное название файлов; try --help");
					return;
				}
				if (output == null)
				{
					Console.WriteLine("Введите корректное название файлов; try --help");
					return;
				}

				// Create a new instance of the Aes
				// class.  This generates a new key and initialization 
				// vector (IV).
				using (Aes myAes = Aes.Create())
				{
					StreamReader sr = new StreamReader(input, System.Text.Encoding.Default);
					string line = sr.ReadLine();
					sr.Close();
					StreamReader sr1 = new StreamReader(key, System.Text.Encoding.Default);
					string key1 = sr1.ReadLine();
					sr1.Close();
					//var Mykey = GenerateSecretKey(key1);
					//var myvector = byte[];
					var myvector = new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76,  0x64, 0x65, 0x76 };
					// Encrypt the string to an array of bytes.

					Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(key1, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });                var Mykey = pdb.GetBytes(32);
					//var myvector= pdb.GetBytes(16);
					StreamWriter SW = new StreamWriter(new FileStream( output, FileMode.Create, FileAccess.Write));
					//byte[] encrypted = EncryptStringToBytes_Aes(line, Encoding.ASCII.GetBytes(Mykey), myvector);	
					if(choose == "e")
					{							
					byte[] encrypted = EncryptStringToBytes_Aes(line, Mykey, myvector);	
					string result = Convert.ToBase64String(encrypted);
						SW.WriteLine("{0}", result);
						SW.Close();
						Console.WriteLine("Original:   {0}", line);
						Console.WriteLine("Encrypted:   {0}", result);
					}
					// Decrypt the bytes to a string.
					if (choose=="d")
					{
						byte[] line1 = Convert.FromBase64String(line);
						string decrypted = DecryptStringFromBytes_Aes(line1, Mykey, myvector);
						//string roundtrip = System.Tet.Encoding.UTF8.GetString(decrypted);
						SW.WriteLine("{0}", decrypted);
						SW.Close();
						Console.WriteLine("Round Trip: {0}", decrypted);
					}				
				}

			}
			catch (Exception e)
			{
				Console.WriteLine("Error: {0}", e.Message);
			}
		}


		public static string GenerateSecretKey (string key)
		{
			StringBuilder result = new StringBuilder ();
			if (key.Length > 32) {
				key.Remove (32);
			}
			if (key.Length == 32)
			{
				return key.ToString ();			
			}

			for (var i = 0; i < 32; i++) {
				var index = i >= key.Length ? i % key.Length : i;
				result.Append (key [index]);					
			}
			return result.ToString ();
		}

	

		static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
		{
			// Check arguments.
			if (plainText == null || plainText.Length <= 0)
				throw new ArgumentNullException("plainText");
			if (Key == null || Key.Length <= 0)
				throw new ArgumentNullException("Key");
			if (IV == null || IV.Length <= 0)
				throw new ArgumentNullException("Key");
			byte[] encrypted;
			// Create an Aes object
			// with the specified key and IV.
			using (Aes aesAlg = Aes.Create())
			{
				aesAlg.Key = Key;
				aesAlg.IV = IV;
				aesAlg.Padding = PaddingMode.PKCS7;
			

				// Create a decrytor to perform the stream transform.
				ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

				// Create the streams used for encryption.
				using (MemoryStream msEncrypt = new MemoryStream())
				{
					using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
						{
							//Write all data to the stream.
							swEncrypt.Write(plainText);
						}
						encrypted = msEncrypt.ToArray();
					}
				}
			}
			// Return the encrypted bytes from the memory stream.
			return encrypted;

		}
	
		static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
		{
			// Check arguments.
			if (cipherText == null || cipherText.Length <= 0)
				throw new ArgumentNullException("cipherText");
			if (Key == null || Key.Length <= 0)
				throw new ArgumentNullException("Key");
			if (IV == null || IV.Length <= 0)
				throw new ArgumentNullException("Key");

			// Declare the string used to hold
			// the decrypted text.
			string plaintext = null;

			// Create an Aes object
			// with the specified key and IV.
			using (Aes aesAlg = Aes.Create())
			{
				aesAlg.Key = Key;
				aesAlg.IV = IV;
				aesAlg.Padding = PaddingMode.PKCS7;

				// Create a decrytor to perform the stream transform.
				ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

				// Create the streams used for decryption.
				using (MemoryStream msDecrypt = new MemoryStream(cipherText))
				{
					using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
					{
						using (StreamReader srDecrypt = new StreamReader(csDecrypt))
						{

							// Read the decrypted bytes from the decrypting stream
								// and place them in a string.
								plaintext = srDecrypt.ReadToEnd();
						}
					}
				}

			}
			return plaintext;
		}
	}
}
