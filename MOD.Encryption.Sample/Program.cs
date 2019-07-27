﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MOD.Encryption.Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            // Private Key ที่ได้จากตอนลงทะเบียน
            string privateKey = "MjA0OCE8UlNBS2V5VmFsdWU+PE1vZHVsdXM+MHc1UlA0bVFhRnNvZENnTnVVdVcvamNiNllEMGtvdXBieWFNZ2hCOWdVLzhnTE1Xc3VVenFoSjl4ckdBUDVEc1B1Yk4zWG53cHpQQnRMaUhYMHNPRjFGaHQ1RXd0ODlHVnE2VXkvOCtXR1puekZaVFhNemtFOFBqZjJURmlycWFlbFh4NDNqNWhMZ0RnMlg5Q1JxZE55RDhmYWk0ZDY5eGc1OHlVTVRiR0RVcUVCSXVPQlpuZVFIVEoyaUwvUFQrYkM1WGZUbW90MFpleVcxQWRGOU1ObmoxMUtJbEc2OTQrOUZiY3hObVpCUUJHeHdTb0g2UDFWWlE3TjFaVkdUK2ZZUElhUHM2bUE0ZzNWZ3Bic2ZrSzRQZ2NTL2o4ekRoRnlLeHMzdkcvZUVMb3diNjZ2ZE9CYlFwOHVwdVlMd29kNzhPekllVExIWFRtb21weWg3MERRPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjYvWDJZMUpicXF2aHpLRFVDTTNUV2JIYnY1bDk1aHU5Qm9ZS3lZWjFUc3U4aDNoelJFZjhEVmtGazZxTWxpVlJjK3BONjk5a2J4N2szVkFheGpGMnFGZXNKRk1DOEJsQ3RTOUR3aktpaWhtUFlJakRVZ0prTmRhaDlIczVJblM2eG1ybTZnRmw1Mlk4dmxNWC9HN3RmUng1SnYwQzd0aWpDZndrazR4MmhITT08L1A+PFE+NVBybGxSNENkTEZXRkl3K0l1WGhLUWxselVXd1M4dDFKNXArZ0JYd0w2VjI5SDVJd0twWmwyczhSUWt1K2tvUjVKbkRqYUZ2NGdYQTQvNUg2UWR2MklxaXBhYVpZdStDSzhuNFZhS3Z4UExvNGo2TjIrMTZXMjFhSkY1dXFnSmpCNXVFdktlcGZONEpjcGoyUTg5RDZwM1k4bm1lQU80NXM5TWNZdGdQQlg4PTwvUT48RFA+UjNtK0pOL3h2SVZNWkx2aS9yZTZhZFVpaDZ0ckk2VUxZVXFCUWdKa3puV1Fxa2ltUWV5OFFSN1NQYVRQNlR0c3JQd3dsbDZaQWNBTis2d2tNQjBUb0hMT1JrS1BCVVBoblJpd0ljZE16U0JvK2dqemdZZ1A2dThWS0FXYmpRQm5BMnVtZndQbFptN2x2NUZVRnJkVFlTNmExR0NYM3Rub3FVR2pvcjVOdUZrPTwvRFA+PERRPjQvb3hUbkFjZmRaNkgrY3BqbEZXQmllSEpnTTJiYUJhT2w0RmlMMU84QUZNR0UwTFhsZTg3NWNpNEpFdUpxQk1oRS9iZFUzQU9VY0ZMM3BpV2s2L090ZDg3SFNjenZZcm9qRnFnTWlEUEJHbGNHeGJqUlk1OW9FL2VHcFV3QXUwVVVTenVha3NoRmdGREFYaldzd25rSllzQSs2Mk03TDczR0JhS01kNDNUMD08L0RRPjxJbnZlcnNlUT5adUZ0M3ZyMnF0cStSLzRmYjZLZUtmUDUxK3FMemZIWUdveDRyQ2IzVGY0ZU1NSVpaeXp3V3QwKzdFd2pkQnJqdTUvR0lkTHRpb1JUL29YZkticGIvZVBUTHJsQVEvN3BacTRCTHZleXNTc2MybXRvY0QyZmY4RE1zR3ZsRkJWN1NtZjN6cGFNZ0c2M3JvM0VDak5qMkNBYW4vTlVWNDZWSXBIbDZoc2ZCdTg9PC9JbnZlcnNlUT48RD54WXZiSkp1QUhRMWwrZ01iaFZwcFJCMFU5U1NNeHpZT0swbHJycm44bnpMYzV5RzVsMHpOWk56VitVcGUvaUNKMy81c3BtYmloNzM4QzBuRSs3N211NUNpNUF6MENyZnA0R3ljUGF6MUVBMGFEcnFtWUhBdTh3a2hRVFp6Wi94dFp5Qld2bEdYUzFCcGlXM0d2K1MzVHNpRFRLTEZ0dER5Y1A1clBBcG1BR3JmZWtWbFpVRHB6WWppQXkwaUJxNWltQ0dyTE84U0VJVTFYbit4cGtuYy9rNmZXTUZ6VFFFVmo4TzEzNTg1VmtTY0tIUDFDeHh3ZlRWbDJESjhVaXU5S2E4YWorZkcyZWozOG0wTFZCWW9zOXhOZ0poQ3lTMGNKa2swUEg4Yk9WUTVzUUg2aFkycTBEQTlMTnllR2hyQmVRd3BQblFZY0pvdk9nMGNUWGFoU1E9PTwvRD48L1JTQUtleVZhbHVlPg==";
            
            // Token ที่เข้ารหัส
            string encryptedToken = "nfUARZLOLuwWuMCMw+qu4UOP7WI/ClfeuwD6spp1qrUb6f4eugwSdaOo97Shj2Sgc4CGmD3Ro/pg3oYbgS7MB1Tzu++fXrqB8BT3JScnnJdgMWUftuvy7I0AE/tpMbO4jrAxTgS8cngL4gxoul81L1MAvejMr1+UoAWSZLmUbrENPX6m3nAceAxWxDFWAzSLAXs/HIailsOgRV/mCt6DPNeiL6gGZn3izvsO1rjEeQe/98X6fxpF1BLVCRrIfh8QXIEcP5oY9TbQI1U2HGUeqwVqekrNPsPRHh87MysT24gkOYc8bemTWvLF9GsbgydDHXQILwsI02VX0zDXdq0MiA==";  

            MOD.Encryption.CryptographyHelper c = new MOD.Encryption.CryptographyHelper(privateKey);

            string token = c.Decrypt(encryptedToken);  // ถอดรหัส Token

            Console.WriteLine(token);

        }
    }
}