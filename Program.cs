Console.WriteLine("Welcome to AES encryption and decryption :" + DateTime.Now);

//Generate an AES key
var key = EncryptionHelper.GenerateKey();

Console.WriteLine("Encryption & Decryption Key: " + key);

//Encrypt the content using the key
var encrypted = EncryptionHelper.Encrypt("This is the string contains all claims for the user.", key);

//Print the encrypted content
Console.WriteLine("Encrypted: " + encrypted);

//Decrypt the content using the key
var decrypted = EncryptionHelper.Decrypt(encrypted, key);

//Print the decrypted content
Console.WriteLine("Decrypted: " + decrypted);

Console.ReadLine();

public static class EncryptionHelper
{
    public static string GenerateKey()
    {
        byte[] key = new byte[32];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(key);
        return BitConverter.ToString(key).Replace("-", "");
    }
    
    /*
     Here is the explanation for the code above:
    1. We have created a byte array of 32 bytes (256 bits) as the key size for AES-256 is 256 bits.
    2. We have used the RandomNumberGenerator.Create() method to create an instance of the default implementation of the RandomNumberGenerator class.
    3. We have used the GetBytes() method of the RandomNumberGenerator class to fill the elements of the key array with cryptographically strong random bytes.
    4. We have used the BitConverter.ToString() method to convert the key byte array to a hexadecimal string and then we have used the Replace() method to remove the hyphens from the hexadecimal string.
    5. We have used the return statement to return the hexadecimal string as the output of the GenerateKey() method. 
    */

    public static string Encrypt(string input, string _key)
    {
        DateTime now = DateTime.UtcNow;

        DateTime expiry = now.AddSeconds(60);

        byte[] expiryBytes = BitConverter.GetBytes(expiry.Ticks);

        byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);
        byte[] encryptedBytes = new byte[inputBytes.Length + expiryBytes.Length];
        inputBytes.CopyTo(encryptedBytes, 0);
        expiryBytes.CopyTo(encryptedBytes, inputBytes.Length);

        byte[] key = System.Text.Encoding.UTF8.GetBytes(_key);

        if (key.Length > 32)
        {
            byte[] temp = new byte[32];
            Array.Copy(key, temp, 32);
            key = temp;
        }

        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = key;
        aes.Mode = System.Security.Cryptography.CipherMode.ECB;
        aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
        using var encryptor = aes.CreateEncryptor();
        byte[] encryptedData = encryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

        string encryptedString = Convert.ToBase64String(encryptedData);

        return encryptedString;
    }

    /*
     Here is the explanation for the code above:
    1. We get the current time in UTC format and add 60 seconds to it. 
    2. We convert that DateTime object to bytes using the BitConverter.GetBytes method. 
    3. We convert the input string to bytes using the System.Text.Encoding.UTF8.GetBytes method. 
    4. We create a byte array of size equal to the input string and the expiry date in bytes. 
    5. We copy the input string bytes into the newly created byte array. 
    6. We copy the expiry date bytes into the newly created byte array. 
    7. We convert the key string to bytes using the System.Text.Encoding.UTF8.GetBytes method. 
    8. If the key is greater than 32 bytes, we trim it to 32 bytes. 
    9. We create a new instance of the Aes class. 
    10. We set the key. 
    11. We set the mode to ECB. 
    12. We set the padding to PKCS7. 
    13. We create an encryptor. 
    14. We encrypt the data using the TransformFinalBlock method. 
    15. We convert the encrypted bytes to a base64 string. 
    16. We return the encrypted string. 
    */

    public static string Decrypt(string input, string _key)
    {
        // Convert the input string from Base64 to a byte array
        byte[] encryptedData = Convert.FromBase64String(input);

        // Decrypt the encrypted byte array using the specified key
        byte[] key = System.Text.Encoding.UTF8.GetBytes(_key);
        if (key.Length > 32)
        {
            byte[] temp = new byte[32];
            Array.Copy(key, temp, 32);
            key = temp;
        }

        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = key;
        aes.Mode = System.Security.Cryptography.CipherMode.ECB;
        aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
        using var decrypt = aes.CreateDecryptor();
        byte[] decryptedData = decrypt.TransformFinalBlock(encryptedData, 0, encryptedData.Length);

        // Extract the input string and expiry date from the decrypted byte array
        const int expiryLength = sizeof(long);
        byte[] inputBytes = new byte[decryptedData.Length - expiryLength];
        Array.Copy(decryptedData, inputBytes, inputBytes.Length);
        byte[] expiryBytes = new byte[expiryLength];
        Array.Copy(decryptedData, inputBytes.Length, expiryBytes, 0, expiryLength);

        // Convert the expiry date byte array to a DateTime object
        long ticks = BitConverter.ToInt64(expiryBytes, 0);
        DateTime expiryDate = new(ticks, DateTimeKind.Utc);

        // Check if the expiry date is within the allowed range
        if (expiryDate < DateTime.UtcNow)
        {
            Console.WriteLine("Input key expired");
            return string.Empty;
        }

        // Convert the input byte array to a string and return it
        string inputString = System.Text.Encoding.UTF8.GetString(inputBytes);
        return inputString;
    }

    /*
     Here is the explanation for the code above:
    1. Convert the input string from Base64 to a byte array
    2.  Decrypt the encrypted byte array using the specified key
    3.  Extract the input string and expiry date from the decrypted byte array
    4.  Convert the expiry date byte array to a DateTime object
    5.  Check if the expiry date is within the allowed range
    6.  Convert the input byte array to a string and return it 
    */
}