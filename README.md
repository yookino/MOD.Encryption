# MOD.Encryption


 // Private Key ที่ได้จากตอนลงทะเบียน
            string privateKey = "";
            
            // Token ที่เข้ารหัส
            string encryptedToken = "";  

            MOD.Encryption.CryptographyHelper c = new MOD.Encryption.CryptographyHelper(privateKey);

            string token = c.Decrypt(encryptedToken);  // ถอดรหัส Token

            Console.WriteLine(token);
