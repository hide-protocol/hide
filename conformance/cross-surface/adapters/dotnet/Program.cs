// Drives the .NET SDK for the cross-surface interop matrix. Two commands:
//   HideAdapter encrypt <public-key> <plaintext> <out-container>
//   HideAdapter decrypt <secret-key> <container> <out-plaintext>
using HideProtocol;

if (args.Length < 4)
{
    Console.Error.WriteLine("usage: HideAdapter encrypt|decrypt <key> <input> <output>");
    return 2;
}

string command = args[0];
byte[] key = File.ReadAllBytes(args[1]);
byte[] input = File.ReadAllBytes(args[2]);
string output = args[3];

switch (command)
{
    case "encrypt":
        File.WriteAllBytes(output, Hide.Encrypt(input, new[] { key }, "dotnet.txt"));
        return 0;
    case "decrypt":
        using (SecretKey secret = SecretKey.Open(key))
        {
            File.WriteAllBytes(output, Hide.Decrypt(input, secret).Plaintext);
        }

        return 0;
    default:
        Console.Error.WriteLine($"unknown command: {command}");
        return 2;
}
