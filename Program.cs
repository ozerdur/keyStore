using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;


class Program
{

    private static string store_password;
    private static string store_path;
    private static string store_alias;
    private static string iv_value;

    private static IConfiguration _configuration;
    private static CryptoUtil _cryptoUtil;


    protected static CryptoUtil GetCryptoUtil(){

        if(_cryptoUtil == null){
            _cryptoUtil = InitializeCryptoUtil();
        }

        return _cryptoUtil;
    }


    static void PrintCommandOptions(){

        Console.WriteLine("Press 1 to create new key store file");
        Console.WriteLine("Press 2 to add new key to key store");
        Console.WriteLine("Press 3 to encrypt new secret");
        Console.WriteLine("Press 4 to decrypt an encrypted secret");
        Console.WriteLine("Press 5 to list all key store values");
        Console.WriteLine("Press 0 to exit");
    }

    
    static void AddNewKeyValueToStoreAndValidate(){

           if(!File.Exists(store_path)){
                Console.WriteLine($"File '{store_path}' does not exist");
                return;
           }

            // Keystore'u yükle
            var loadedKeyStore = new KeyStore();
            loadedKeyStore.Load(store_path, store_password);
            Console.WriteLine("Keystore yüklendi.");

            Console.Write("Enter KeyStore Key: ");
            string enteredAlias = Console.ReadLine();

            Console.Write("Enter KeyStore Value: ");
            string enteredValue = Console.ReadLine();

            var enteredValueBytes = Encoding.UTF8.GetBytes(enteredValue);

            loadedKeyStore.AddKey(enteredAlias, enteredValueBytes);
            Console.WriteLine($"Key '{enteredAlias}' eklendi ve şifreleniyor...");
            
            // Keystore'u dosyaya kaydet
            loadedKeyStore.Save(store_path, store_password);

            Console.WriteLine($"Keystore '{store_path}' konumuna şifreli olarak kaydedildi.");
            
            //key i yeniden al
            loadedKeyStore.Load(store_path, store_password);

            // Anahtarı getir ve doğrula
            var retrievedKey = loadedKeyStore.GetKey(enteredAlias);
            Console.WriteLine($"Key '{enteredAlias}' başarıyla geri alındı: {Encoding.UTF8.GetString(retrievedKey)}");

            // Anahtarların eşleştiğini kontrol et
            Console.WriteLine($"Anahtar eşleşmesi: {AreKeysEqual(enteredValueBytes, retrievedKey)}");
    }


    static void ListAllKeyStoreKeyValues(){
           if(!File.Exists(store_path)){
                Console.WriteLine($"File '{store_path}' does not exist");
                return;
           }
            // Keystore'u yükle
            var loadedKeyStore = new KeyStore();
            loadedKeyStore.Load(store_path, store_password);
            Console.WriteLine("Keystore yüklendi.");

            loadedKeyStore.ListAllKeyValues();

    }


    static void CreateNewKeyStoreAndValidate(){

            Console.Write("Enter KeyStore Key: ");
            string enteredKey = Console.ReadLine();

            var enteredKeyBytes = Encoding.UTF8.GetBytes(enteredKey);

            KeyStore keyStore = new KeyStore();
            keyStore.AddKey(store_alias, enteredKeyBytes);
            Console.WriteLine($"Key '{store_alias}' eklendi ve şifreleniyor...");
            
            // Keystore'u dosyaya kaydet
            keyStore.Save(store_path, store_password);

            Console.WriteLine($"Keystore '{store_path}' konumuna şifreli olarak kaydedildi.");
            
            // Keystore'u yükle
            var loadedKeyStore = new KeyStore();
            loadedKeyStore.Load(store_path, store_password);
            Console.WriteLine("Keystore yüklendi.");

            // Anahtarı getir ve doğrula
            var retrievedKey = loadedKeyStore.GetKey(store_alias);
            Console.WriteLine($"Key '{store_alias}' başarıyla geri alındı: {Encoding.UTF8.GetString(retrievedKey)}");

            // Anahtarların eşleştiğini kontrol et
            Console.WriteLine($"Anahtar eşleşmesi: {AreKeysEqual(enteredKeyBytes, retrievedKey)}");
    }

    static CryptoUtil InitializeCryptoUtil(){
            // Keystore'u yükle
            var loadedKeyStore = new KeyStore();
            loadedKeyStore.Load(store_path, store_password);
            Console.WriteLine("Keystore yüklendi.");
            var key = loadedKeyStore.GetKey(store_alias);

            return new CryptoUtil(key, Encoding.UTF8.GetBytes(iv_value));
    }

    static void Main()
    {
        LoadConfig();
        
        string command = string.Empty;
        do
        {
            PrintCommandOptions();
            command = Console.ReadLine();
            switch(command){
                case "1" : 
                    CreateNewKeyStoreAndValidate();
                    break;

                case "2":
                    AddNewKeyValueToStoreAndValidate();
                    break;

                case "3":
                    if(!File.Exists(store_path)){
                        Console.WriteLine($"File '{store_path}' does not exist");
                        break;
                    }
                    Console.WriteLine("Enter secret to encrypt");
                    var secret = Console.ReadLine();
                    Console.WriteLine($"EncryptedSecret: '{GetCryptoUtil().Encrypt(secret)}'");
                    break;

                case "4":
                    if(!File.Exists(store_path)){
                        Console.WriteLine($"File '{store_path}' does not exist");
                        break;
                    }
                    Console.WriteLine("Enter text to decrypt");
                    var encryptedSecret = Console.ReadLine();
                    Console.WriteLine($"Plain secret: '{GetCryptoUtil().Decrypt(encryptedSecret)}'");
                    break;

                case "5":
                    ListAllKeyStoreKeyValues();
                    break;

                default:
                    break;
            }

            if(!string.IsNullOrEmpty(command) && command.Equals("0")){
                break;
            }
        } while (true);
    }


    private  static void LoadConfig(){

        var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("config.json");


        _configuration = builder.Build();
        
        store_password = _configuration[StringConstants.store_password_key] ?? throw new ArgumentNullException(StringConstants.store_password_key);
        store_path = _configuration[StringConstants.store_path_key] ?? throw new ArgumentNullException(StringConstants.store_path_key);
        store_alias = _configuration[StringConstants.store_alias_key] ?? throw new ArgumentNullException(StringConstants.store_alias_key);
        iv_value = _configuration[StringConstants.iv_value_key] ?? throw new ArgumentNullException(StringConstants.iv_value_key); 


    }
    private static byte[] GenerateRandomKey()
    {
        using var rng = RandomNumberGenerator.Create();
        var key = new byte[32]; // 256-bit anahtar
        rng.GetBytes(key);
        return key;
    }
    

    private static bool AreKeysEqual(byte[] key1, byte[] key2)
    {
        if (key1.Length != key2.Length)
            return false;

        for (int i = 0; i < key1.Length; i++)
        {
            if (key1[i] != key2[i])
                return false;
        }

        return true;
    }
}
