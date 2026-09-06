using System.Text;
using HideProtocol;
using Xunit;

namespace HideProtocol.Tests;

public class HideTests
{
    [Fact]
    public void RoundTripCarriesMetadata()
    {
        using SecretKey secret = SecretKey.Generate();
        byte[] publicKey = secret.PublicKey();
        Assert.Equal(Hide.PublicKeyLength, publicKey.Length);

        byte[] plaintext = Encoding.UTF8.GetBytes("nume,suma\nAna,9000\n");
        byte[] box = Hide.Encrypt(plaintext, [publicKey], "salarii.csv", "text/csv");

        Assert.DoesNotContain("Ana", Encoding.Latin1.GetString(box));

        Decrypted opened = Hide.Decrypt(box, secret);
        Assert.Equal(plaintext, opened.Plaintext);
        Assert.Equal("salarii.csv", opened.FileName);
        Assert.Equal("text/csv", opened.MediaType);
    }

    [Fact]
    public void MetadataContainingNulIsReadBackIntact()
    {
        // The C ABI takes metadata NUL-terminated, so a container carrying an
        // embedded NUL cannot be produced through Encrypt; it can only arrive
        // from a hostile writer. What must not truncate is the DECODE side,
        // which reads a length-prefixed buffer and never scans for a terminator.
        byte[] raw = Encoding.UTF8.GetBytes("safe.txt\0../../etc/passwd");
        Assert.Equal("safe.txt\0../../etc/passwd", Interop.DecodeText(raw));
        Assert.Equal(25, Interop.DecodeText(raw)!.Length);

        // And the outbound direction refuses rather than silently truncating.
        using SecretKey secret = SecretKey.Generate();
        byte[] publicKey = secret.PublicKey();
        Assert.Throws<ArgumentException>(() =>
            Hide.Encrypt("x"u8, [publicKey], "safe.txt\0evil"));
        Assert.Throws<ArgumentException>(() =>
            Hide.Encrypt("x"u8, [publicKey], null, "text/pl\0ain"));
    }

    [Fact]
    public void MetadataWithUnusualCharactersSurvives()
    {
        using SecretKey secret = SecretKey.Generate();
        const string name = "raport ăîșț — 100%.csv";

        byte[] box = Hide.Encrypt("x"u8, [secret.PublicKey()], name, "text/csv; charset=utf-8");
        Decrypted opened = Hide.Decrypt(box, secret);

        Assert.Equal(name, opened.FileName);
        Assert.Equal("text/csv; charset=utf-8", opened.MediaType);
    }

    [Fact]
    public void EverySingleByteMutationIsRejected()
    {
        using SecretKey secret = SecretKey.Generate();
        byte[] box = Hide.Encrypt("confidential"u8, [secret.PublicKey()]);

        foreach (int offset in new[] { 0, 8, 15, 40, box.Length / 2, box.Length - 20, box.Length - 1 })
        {
            byte[] damaged = (byte[])box.Clone();
            damaged[offset] ^= 0x40;
            Assert.ThrowsAny<HideException>(() => Hide.Decrypt(damaged, secret));
        }
    }

    [Fact]
    public void TruncationAndExtensionFail()
    {
        using SecretKey secret = SecretKey.Generate();
        byte[] box = Hide.Encrypt("payload"u8, [secret.PublicKey()]);

        Assert.ThrowsAny<HideException>(() => Hide.Decrypt(box.AsSpan(0, box.Length - 1).ToArray(), secret));
        Assert.ThrowsAny<HideException>(() => Hide.Decrypt([.. box, (byte)0], secret));
    }

    [Fact]
    public void TheWrongKeyCannotDecrypt()
    {
        using SecretKey alice = SecretKey.Generate();
        using SecretKey bob = SecretKey.Generate();

        byte[] box = Hide.Encrypt("for alice"u8, [alice.PublicKey()]);
        Assert.Throws<NoMatchingRecipientException>(() => Hide.Decrypt(box, bob));
    }

    [Fact]
    public void ManyRecipientsShareOnePayload()
    {
        SecretKey[] keys = [SecretKey.Generate(), SecretKey.Generate(), SecretKey.Generate()];
        try
        {
            byte[] box = Hide.Encrypt("shared"u8, [.. keys.Select(key => key.PublicKey())]);
            foreach (SecretKey key in keys)
            {
                Assert.Equal("shared"u8.ToArray(), Hide.Decrypt(box, key).Plaintext);
            }
        }
        finally
        {
            foreach (SecretKey key in keys)
            {
                key.Dispose();
            }
        }
    }

    [Fact]
    public void ProtectedKeysRoundTrip()
    {
        byte[] publicKey;
        byte[] sealedKey;
        using (SecretKey secret = SecretKey.Generate())
        {
            publicKey = secret.PublicKey();
            sealedKey = secret.Protect("correct horse battery");
        }

        Assert.Equal(KeyKind.Protected, Hide.InspectKey(sealedKey));

        Assert.Throws<WrongPassphraseException>(() => SecretKey.Open(sealedKey, "wrong passphrase"));
        Assert.Throws<WrongPassphraseException>(() => SecretKey.Open(sealedKey));

        using SecretKey reopened = SecretKey.Open(sealedKey, "correct horse battery");
        Assert.Equal(publicKey, reopened.PublicKey());
    }

    [Fact]
    public void AShortPassphraseIsRefused()
    {
        using SecretKey secret = SecretKey.Generate();
        Assert.Throws<ArgumentException>(() => secret.Protect("short"));
    }

    [Fact]
    public void ArmorRoundTrips()
    {
        using SecretKey secret = SecretKey.Generate();
        byte[] publicKey = secret.PublicKey();

        string text = Hide.ArmorPublicKey(publicKey);
        Assert.StartsWith("hide-public-key:", text);
        Assert.Equal(publicKey, Hide.DearmorPublicKey(text));
        Assert.ThrowsAny<HideException>(() => Hide.DearmorPublicKey("not a key"));
    }

    [Fact]
    public void RecipientCountAndKeyLengthAreBounded()
    {
        using SecretKey secret = SecretKey.Generate();
        byte[] publicKey = secret.PublicKey();

        Assert.Throws<ArgumentException>(() => Hide.Encrypt("x"u8, []));
        Assert.Throws<ArgumentException>(() =>
            Hide.Encrypt("x"u8, [.. Enumerable.Repeat(publicKey, 65)]));
        Assert.Throws<ArgumentException>(() => Hide.Encrypt("x"u8, [Encoding.UTF8.GetBytes("too short")]));
    }

    [Fact]
    public void ADisposedKeyIsUnusableAndNeverPrintsKeyMaterial()
    {
        SecretKey secret = SecretKey.Generate();
        byte[] publicKey = secret.PublicKey();

        string rendered = secret.ToString();
        Assert.Contains("SecretKey", rendered);
        Assert.DoesNotContain(Convert.ToHexString(publicKey)[..16], rendered, StringComparison.OrdinalIgnoreCase);

        secret.Dispose();
        secret.Dispose();

        Assert.Throws<ObjectDisposedException>(() => secret.PublicKey());
        Assert.Throws<ObjectDisposedException>(() => secret.Protect("correct horse battery"));
        Assert.Contains("disposed", secret.ToString());
    }

    [Fact]
    public void EmptyPayloadsAreValid()
    {
        using SecretKey secret = SecretKey.Generate();
        byte[] box = Hide.Encrypt([], [secret.PublicKey()]);
        Decrypted opened = Hide.Decrypt(box, secret);

        Assert.Empty(opened.Plaintext);
        Assert.Null(opened.FileName);
        Assert.Null(opened.MediaType);
    }

    [Fact]
    public void GarbageIsRejectedRatherThanCrashing()
    {
        using SecretKey secret = SecretKey.Generate();

        Assert.ThrowsAny<Exception>(() => Hide.Decrypt(new byte[64], secret));
        Assert.ThrowsAny<Exception>(() => Hide.Decrypt([], secret));
        Assert.ThrowsAny<Exception>(() => SecretKey.Open(Encoding.UTF8.GetBytes("not a key at all")));
        Assert.ThrowsAny<Exception>(() => SecretKey.Open([]));

        // InspectKey is a cheap classifier, not a validator: it must answer
        // without crashing, whatever it is handed.
        Assert.True(Enum.IsDefined(Hide.InspectKey(Encoding.UTF8.GetBytes("nonsense"))));
        Assert.True(Enum.IsDefined(Hide.InspectKey([])));
    }

    [Fact]
    public void VersionIsReported()
    {
        Assert.False(string.IsNullOrWhiteSpace(Hide.Version));
    }
}
