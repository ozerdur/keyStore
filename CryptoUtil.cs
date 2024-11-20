
using System.Security.Cryptography;
using System.Text;
class CryptoUtil{
    private byte[] _ivBytes;
    private byte[] _key;

    public CryptoUtil(byte[] key, byte[] ivBytes)
    {
      _ivBytes = ivBytes;   
      _key = key;
    }

    public string Encrypt(string data)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = _key;
            aes.IV = _ivBytes;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] encryptedBytes = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
                return Convert.ToBase64String(encryptedBytes);
            }
        }
    }

    public  string Decrypt(string encryptedData)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = _key;
            aes.IV = _ivBytes;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData);
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
    }
}