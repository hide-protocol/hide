using System.Text;
using HideProtocol;
using Xunit;

namespace HideProtocol.Tests;

public class SigningTests
{
    private const string Passphrase = "correct horse battery";
    private static ReadOnlySpan<byte> Context => "example/dotnet test"u8;

    private static SigningIdentity Identity() =>
        SigningIdentity.Load(SigningIdentity.Generate(Passphrase), Passphrase);

    [Fact]
    public void SignsAndVerifies()
    {
        using SigningIdentity signer = Identity();
        byte[] publicKey = signer.PublicKey();
        Assert.Equal(Hide.VerifyingKeyLength, publicKey.Length);

        byte[] signature = signer.Sign(Context, "the message"u8);
        Assert.Equal(Hide.SignatureLength, signature.Length);

        Hide.Verify(publicKey, Context, "the message"u8, signature);
    }

    [Fact]
    public void AChangedMessageDoesNotVerify()
    {
        using SigningIdentity signer = Identity();
        byte[] signature = signer.Sign(Context, "the message"u8);

        Assert.Throws<AuthenticationException>(() =>
            Hide.Verify(signer.PublicKey(), Context, "the messagE"u8, signature));
    }

    [Fact]
    public void ADifferentContextDoesNotVerify()
    {
        using SigningIdentity signer = Identity();
        byte[] signature = signer.Sign(Context, "the message"u8);

        Assert.Throws<AuthenticationException>(() =>
            Hide.Verify(signer.PublicKey(), "another context"u8, "the message"u8, signature));
    }

    [Fact]
    public void AnotherIdentityCannotBeImpersonated()
    {
        using SigningIdentity signer = Identity();
        using SigningIdentity impostor = Identity();
        byte[] signature = impostor.Sign(Context, "the message"u8);

        Assert.Throws<AuthenticationException>(() =>
            Hide.Verify(signer.PublicKey(), Context, "the message"u8, signature));
    }

    // Spec §15.2: the generic API must not mint protocol signatures.
    [Theory]
    [InlineData("HIDE/0.6 identity entry")]
    [InlineData("HIDE/1.0 container")]
    [InlineData("HIDE/")]
    public void ReservedProtocolContextsAreRefused(string context)
    {
        using SigningIdentity signer = Identity();
        Assert.Throws<ArgumentException>(() =>
            signer.Sign(Encoding.UTF8.GetBytes(context), "the message"u8));
    }

    [Fact]
    public void AnEncryptionOnlyKeyCannotSign()
    {
        byte[] sealedKey;
        using (SecretKey secret = SecretKey.Generate())
        {
            sealedKey = secret.Protect(Passphrase);
        }

        Assert.Throws<NotAKeyException>(() => SigningIdentity.Load(sealedKey, Passphrase));
    }

    [Fact]
    public void AChallengeIsAnsweredOnceAndThenRefused()
    {
        using SigningIdentity prover = Identity();
        byte[] publicKey = prover.PublicKey();
        byte[] challenge = Hide.NewChallenge("ssh://host.example", 1_000, 60);
        byte[] answer = prover.Answer(challenge);

        using SpentNonces spent = new("ssh://host.example");
        spent.Accept(challenge, answer, publicKey, 1_000);

        // The identical valid answer, presented again.
        Assert.Throws<ChallengeReplayedException>(() =>
            spent.Accept(challenge, answer, publicKey, 1_000));
    }

    [Fact]
    public void AnAnswerAfterTheWindowIsRefused()
    {
        using SigningIdentity prover = Identity();
        byte[] publicKey = prover.PublicKey();
        byte[] challenge = Hide.NewChallenge("ssh://host.example", 1_000, 60);
        byte[] answer = prover.Answer(challenge);

        using SpentNonces spent = new("ssh://host.example");
        Assert.Throws<ChallengeExpiredException>(() =>
            spent.Accept(challenge, answer, publicKey, 1_100));
    }

    // The record knows which service it answers for, so a challenge relayed
    // from elsewhere is refused even though the answer is a genuine signature
    // that would verify on its own.
    [Fact]
    public void AnAnswerForAnotherAudienceIsRefused()
    {
        using SigningIdentity prover = Identity();
        byte[] publicKey = prover.PublicKey();
        byte[] relayed = Hide.NewChallenge("https://elsewhere.test", 1_000, 60);
        byte[] answer = prover.Answer(relayed);

        using SpentNonces spent = new("https://example.test");
        Assert.Throws<ChallengeAudienceException>(() =>
            spent.Accept(relayed, answer, publicKey, 1_010));

        // The audience this record does answer to is unaffected.
        byte[] ours = Hide.NewChallenge("https://example.test", 1_000, 60);
        spent.Accept(ours, prover.Answer(ours), publicKey, 1_010);
    }

    // Failing closed: a verifier that forgot to name its audience refuses every
    // answer rather than accepting one minted for anyone.
    [Fact]
    public void ARecordBuiltWithAnEmptyAudienceAcceptsNothing()
    {
        using SigningIdentity prover = Identity();
        byte[] publicKey = prover.PublicKey();
        byte[] challenge = Hide.NewChallenge("https://example.test", 1_000, 60);
        byte[] answer = prover.Answer(challenge);

        using SpentNonces spent = new("");
        Assert.Throws<ChallengeAudienceException>(() =>
            spent.Accept(challenge, answer, publicKey, 1_010));
    }

    [Fact]
    public void ADisposedIdentityCannotSignAndNeverPrintsKeyMaterial()
    {
        SigningIdentity signer = Identity();
        byte[] publicKey = signer.PublicKey();

        string rendered = signer.ToString();
        Assert.Contains("SigningIdentity", rendered);
        Assert.DoesNotContain(
            Convert.ToHexString(publicKey)[..16], rendered, StringComparison.OrdinalIgnoreCase);

        signer.Dispose();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => signer.Sign(Context, "anything"u8));
        Assert.Throws<ObjectDisposedException>(() => signer.PublicKey());
        Assert.Contains("disposed", signer.ToString());
    }

    [Fact]
    public void AShortPassphraseIsRefusedForAnIdentity()
    {
        Assert.Throws<ArgumentException>(() => SigningIdentity.Generate("short"));
        Assert.Throws<ArgumentException>(() => SigningIdentity.Generate("a\0b\0c\0d\0e"));
    }

    [Fact]
    public void GarbageIsRejectedRatherThanCrashing()
    {
        Assert.ThrowsAny<HideException>(() =>
            SigningIdentity.Load(Encoding.UTF8.GetBytes("not a key at all"), Passphrase));
        Assert.ThrowsAny<HideException>(() => SigningIdentity.Load([], Passphrase));
    }
}
