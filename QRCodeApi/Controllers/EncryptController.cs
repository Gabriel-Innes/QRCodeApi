using Microsoft.AspNetCore.Mvc;
using QRCoder;
using System.Security.Cryptography;

namespace QrCodeAPI.Controllers
{
    [ApiController]
    [Route("api/encrypt")]
    public class EncryptController : ControllerBase
    {
        private static readonly string Password = "ReachYourPeak"; // Change this!

        [HttpPost]
        public IActionResult EncryptJson([FromBody] object jsonData)
        {
            if (jsonData == null)
                return BadRequest("Invalid JSON data");

            string jsonString = System.Text.Json.JsonSerializer.Serialize(jsonData);
            byte[] encryptedData = EncryptJsonData(jsonString);
            byte[] qrCodeBytes = GenerateQrCode(encryptedData);

            return File(qrCodeBytes, "image/png");
        }

        private byte[] EncryptJsonData(string jsonData)
        {
            byte[] salt = GenerateRandomSalt();
            using (Aes aes = Aes.Create())
            {
                using (var key = new Rfc2898DeriveBytes(Password, salt, 10000))
                {
                    aes.Key = key.GetBytes(32); // AES-256
                    aes.GenerateIV();

                    using (MemoryStream ms = new MemoryStream())
                    {
                        ms.Write(salt, 0, salt.Length);
                        ms.Write(aes.IV, 0, aes.IV.Length);

                        using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(jsonData);
                            sw.Flush();
                        }

                        return ms.ToArray();
                    }
                }
            }
        }

        private byte[] GenerateQrCode(byte[] encryptedData)
        {
            string base64Encrypted = Convert.ToBase64String(encryptedData);
            using (QRCodeGenerator qrGenerator = new QRCodeGenerator())
            using (QRCodeData qrCodeData = qrGenerator.CreateQrCode(base64Encrypted, QRCodeGenerator.ECCLevel.Q))
            using (PngByteQRCode qrCode = new PngByteQRCode(qrCodeData))
            {
                return qrCode.GetGraphic(20);
            }
        }

        private byte[] GenerateRandomSalt()
        {
            byte[] salt = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }
    }

}
