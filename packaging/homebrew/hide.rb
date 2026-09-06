# Formula for the hide-protocol/homebrew-hide tap.
#
# The release workflow rewrites the version and the four checksums, so this
# file is the template rather than something edited by hand.
class Hide < Formula
  desc "Experimental hybrid post-quantum file and message encryption (unaudited)"
  homepage "https://github.com/hide-protocol/hide"
  version "0.2.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/hide-protocol/hide/releases/download/v#{version}/hide-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_MACOS_ARM64"
    end
    on_intel do
      url "https://github.com/hide-protocol/hide/releases/download/v#{version}/hide-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_MACOS_X86_64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/hide-protocol/hide/releases/download/v#{version}/hide-v#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_LINUX_ARM64"
    end
    on_intel do
      url "https://github.com/hide-protocol/hide/releases/download/v#{version}/hide-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_LINUX_X86_64"
    end
  end

  def install
    bin.install Dir["*/hide"].first || "hide"
    doc.install Dir["*/README.md"].first if Dir["*/README.md"].any?
    doc.install Dir["*/SECURITY.md"].first if Dir["*/SECURITY.md"].any?
  end

  def caveats
    <<~EOS
      HIDE is experimental and has not been independently audited.

      Do not use it to protect data you cannot afford to lose or expose. A
      successful decryption proves the data was not altered; it does NOT prove
      who sent it. Every command requires --experimental so the risk is
      acknowledged explicitly.

      The wire format may change while the version is 0.x.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/hide --version")

    # A real round trip, so the bottle cannot pass while being unusable.
    system bin/"hide", "--experimental", "--quiet", "keygen",
           "--secret", "k.key", "--public", "k.pub", "--insecure-plaintext"
    (testpath/"message.txt").write "homebrew"
    system bin/"hide", "--experimental", "--quiet", "encrypt", "message.txt",
           "--recipient", "k.pub", "--output", "message.hide"
    system bin/"hide", "--experimental", "--quiet", "open", "message.hide",
           "--secret", "k.key", "--output", "out.txt"
    assert_equal "homebrew", (testpath/"out.txt").read
  end
end
