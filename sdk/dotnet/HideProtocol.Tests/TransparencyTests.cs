using System.Text;
using HideProtocol;
using Xunit;

namespace HideProtocol.Tests;

public class TransparencyTests
{
    [Fact]
    public void AnIdentityLogReportsTheDevicesItTrusts()
    {
        // Four events: create, enrol phone, enrol laptop, revoke laptop.
        Assert.Equal(2, Hide.VerifyIdentity(Fixtures.IdentityLog, Fixtures.IdentityRecovery));
    }

    [Fact]
    public void ARevokedDeviceIsNoLongerTrusted()
    {
        Assert.True(Hide.IdentityTrustsDevice(
            Fixtures.IdentityLog, Fixtures.IdentityRecovery, Fixtures.IdentityDevicePhone));
        Assert.False(Hide.IdentityTrustsDevice(
            Fixtures.IdentityLog, Fixtures.IdentityRecovery, Fixtures.IdentityDeviceLaptop));
    }

    [Fact]
    public void ATamperedLogIsRefused()
    {
        Assert.Throws<AuthenticationException>(() =>
            Hide.VerifyIdentity(Fixtures.IdentityTampered, Fixtures.IdentityRecovery));

        // Bytes that do not decode at all are a different failure from bytes
        // that decode and do not verify.
        Assert.Throws<MalformedException>(() =>
            Hide.VerifyIdentity(Encoding.UTF8.GetBytes("not a log"), Fixtures.IdentityRecovery));
    }

    [Fact]
    public void TheHeadNamesThisExactHistory()
    {
        byte[] head = Hide.IdentityHead(Fixtures.IdentityLog, Fixtures.IdentityRecovery);
        Assert.Equal(32, head.Length);
        Assert.Equal(Fixtures.IdentityHead, head);
    }

    [Fact]
    public void AnEpochChainVerifiesAndYieldsKeys()
    {
        Assert.Equal(3, Hide.VerifyEpochChain(Fixtures.EpochChain));
        Assert.Equal(Fixtures.EpochPublicKey1, Hide.EpochPublicKey(Fixtures.EpochChain, 1));
    }

    [Fact]
    public void AnEpochBeyondTheChainIsRefused() =>
        Assert.Throws<ArgumentException>(() => Hide.EpochPublicKey(Fixtures.EpochChain, 3));

    [Fact]
    public void ASplicedEpochChainDoesNotVerify() =>
        Assert.Throws<AuthenticationException>(() => Hide.VerifyEpochChain(Fixtures.EpochBroken));

    [Fact]
    public void AnInclusionProofVerifiesOnlyForItsOwnLeaf()
    {
        Hide.VerifyInclusion(Fixtures.Leaf, 3, 8, Fixtures.InclusionPath, Fixtures.TreeRoot);

        Assert.Throws<AuthenticationException>(() =>
            Hide.VerifyInclusion(Fixtures.OtherLeaf, 3, 8, Fixtures.InclusionPath, Fixtures.TreeRoot));
    }

    [Fact]
    public void APathThatIsNotWholeHashesIsRefused()
    {
        byte[] truncated = Fixtures.InclusionPath[..^1];

        Assert.Throws<ArgumentException>(() =>
            Hide.VerifyInclusion(Fixtures.Leaf, 3, 8, truncated, Fixtures.TreeRoot));
    }

    [Fact]
    public void AConsistencyProofCatchesARewrittenHistory()
    {
        Hide.VerifyConsistency(5, 8, Fixtures.ConsistencyPath, Fixtures.RootAt5, Fixtures.TreeRoot);

        // Same size, one entry silently replaced.
        Assert.Throws<AuthenticationException>(() =>
            Hide.VerifyConsistency(
                5, 8, Fixtures.ConsistencyPath, Fixtures.RootAt5, Fixtures.RewrittenRoot));
    }

    [Fact]
    public void APinnedIdentityVerifiesAgainstItsRoot() =>
        Assert.Equal(2, Hide.VerifyIdentityPinned(
            Fixtures.BindingIdentityLog, Fixtures.BindingRecovery, Fixtures.BindingRoot));

    [Fact]
    public void AHijackedIdentityIsRefused()
    {
        // A Recover appended under a stranger's key, with the genuine binding
        // and with one forged for the stranger.
        Assert.Throws<AuthenticationException>(() => Hide.VerifyIdentityPinned(
            Fixtures.BindingHijackedLog, Fixtures.BindingRecovery, Fixtures.BindingRoot));
        Assert.Throws<AuthenticationException>(() => Hide.VerifyIdentityPinned(
            Fixtures.BindingHijackedLog, Fixtures.BindingRecoveryForged, Fixtures.BindingRoot));
    }

    [Fact]
    public void AnotherRootIsRefused() =>
        Assert.Throws<AuthenticationException>(() => Hide.VerifyIdentityPinned(
            Fixtures.BindingIdentityLog, Fixtures.BindingRecovery, new byte[32]));

    [Fact]
    public void ATruncatedRecoveryBindingIsMalformed() =>
        Assert.Throws<MalformedException>(() => Hide.VerifyIdentityPinned(
            Fixtures.BindingIdentityLog, Fixtures.BindingRecovery[..100], Fixtures.BindingRoot));

    [Fact]
    public void AnEpochChainBoundToThePinnedIdentityVerifies() =>
        Assert.Equal(3, Hide.VerifyEpochChainBound(
            Fixtures.BindingIdentityLog,
            Fixtures.BindingRecovery,
            Fixtures.BindingRoot,
            Fixtures.EpochChain,
            Fixtures.BindingEpoch));

    [Fact]
    public void AnEpochChainSignedByAStrangerIsRefused() =>
        Assert.Throws<AuthenticationException>(() => Hide.VerifyEpochChainBound(
            Fixtures.BindingIdentityLog,
            Fixtures.BindingRecovery,
            Fixtures.BindingRoot,
            Fixtures.EpochChain,
            Fixtures.BindingEpochStranger));

    [Fact]
    public void ACheckpointYieldsItsSizeAndRoot()
    {
        (ulong size, byte[] root) =
            Hide.VerifyCheckpoint(Fixtures.Checkpoint3, "log.example/hide", Fixtures.CheckpointLogKey);
        Assert.Equal(3UL, size);
        Assert.Equal(32, root.Length);
    }

    [Fact]
    public void ACheckpointIsRefusedUnlessEverythingMatches()
    {
        Assert.Throws<AuthenticationException>(() => Hide.VerifyCheckpoint(
            Fixtures.CheckpointTampered, "log.example/hide", Fixtures.CheckpointLogKey));
        Assert.Throws<AuthenticationException>(() => Hide.VerifyCheckpoint(
            Fixtures.Checkpoint3, "other.example", Fixtures.CheckpointLogKey));
        Assert.Throws<AuthenticationException>(() => Hide.VerifyCheckpoint(
            Fixtures.Checkpoint3, "log.example/hide", Fixtures.CheckpointWitnessKey));
    }
}
