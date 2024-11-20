using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

class KeyStore
{
    private readonly Dictionary<string, string> _store = new();

    public void AddKey(string alias, byte[] key)
    {
        _store[alias] = Convert.ToBase64String(key);
    }

    public byte[] GetKey(string alias)
    {
        if (_store.TryGetValue(alias, out var base64Key))
        {
            return Convert.FromBase64String(base64Key);
        }
        throw new KeyNotFoundException("Key not found.");
    }

    public void Save(string filePath, string password)
    {
        var encryptedStore = Encrypt(JsonSerializer.Serialize(_store), password);
        File.WriteAllText(filePath, encryptedStore);
    }

    public void Load(string filePath, string password)
    {
        var encryptedStore = File.ReadAllText(filePath);
        var decryptedStore = Decrypt(encryptedStore, password);
        var deserializedStore = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedStore);
        if (deserializedStore != null)
        {
            foreach (var kvp in deserializedStore)
            {
                _store[kvp.Key] = kvp.Value;
            }
        }
    }

    private static string Encrypt(string plainText, string password)
    {
        using var aes = Aes.Create();
        var key = Encoding.UTF8.GetBytes(password.PadRight(32).Substring(0, 32));
        aes.Key = key;
        aes.IV = key.Take(16).ToArray();
        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        using var sw = new StreamWriter(cs);
        sw.Write(plainText);
        sw.Close();
        return Convert.ToBase64String(ms.ToArray());
    }

    private static string Decrypt(string cipherText, string password)
    {
        using var aes = Aes.Create();
        var key = Encoding.UTF8.GetBytes(password.PadRight(32).Substring(0, 32));
        aes.Key = key;
        aes.IV = key.Take(16).ToArray();
        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(Convert.FromBase64String(cipherText));
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs);
        return sr.ReadToEnd();
    }

    public void ListAllKeyValues(){
        foreach (var kvp in _store)
        {
            Console.WriteLine($"Key: {kvp.Key}, Value: {Encoding.UTF8.GetString(Convert.FromBase64String(kvp.Value))}");
        }
    }
}
