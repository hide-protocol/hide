# frozen_string_literal: true

# Exercises the Ruby SDK against the real native library.

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "minitest/autorun"
require "hide_protocol"

class TestHide < Minitest::Test
  def test_round_trip_carries_metadata
    Hide::SecretKey.generate do |secret|
      public_key = secret.public_key
      assert_equal Hide::PUBLIC_KEY_LEN, public_key.bytesize
      assert_equal Encoding::BINARY, public_key.encoding

      box = Hide.encrypt(
        "nume,suma\nAna,9000\n",
        recipients: [public_key],
        filename: "salarii.csv",
        media_type: "text/csv"
      )
      assert_equal Encoding::BINARY, box.encoding
      refute_includes box, "Ana", "plaintext leaked into the container"

      opened = Hide.decrypt(box, secret)
      assert_equal "nume,suma\nAna,9000\n".b, opened.plaintext
      assert_equal "salarii.csv", opened.filename
      assert_equal "text/csv", opened.media_type
    end
  end

  def test_every_single_byte_mutation_is_rejected
    Hide::SecretKey.generate do |secret|
      box = Hide.encrypt("confidential", recipients: [secret.public_key])
      # Sampling the regions that matter rather than all ~1.3 kB, to keep the
      # suite fast; the Rust side tests every byte exhaustively.
      offsets = [0, 8, 15, 40, box.bytesize / 2, box.bytesize - 20, box.bytesize - 1]
      offsets.each do |offset|
        damaged = box.dup
        damaged.setbyte(offset, damaged.getbyte(offset) ^ 0x40)
        assert_raises(Hide::Error, "offset #{offset} was accepted") do
          Hide.decrypt(damaged, secret)
        end
      end
    end
  end

  def test_truncation_and_extension_fail
    Hide::SecretKey.generate do |secret|
      box = Hide.encrypt("payload", recipients: [secret.public_key])
      assert_raises(Hide::Error) { Hide.decrypt(box[0...-1], secret) }
      assert_raises(Hide::Error) { Hide.decrypt(box + "\x00".b, secret) }
    end
  end

  def test_the_wrong_key_cannot_decrypt
    Hide::SecretKey.generate do |alice|
      Hide::SecretKey.generate do |bob|
        box = Hide.encrypt("for alice", recipients: [alice.public_key])
        assert_raises(Hide::NoMatchingRecipientError) { Hide.decrypt(box, bob) }
      end
    end
  end

  def test_many_recipients_share_one_payload
    keys = Array.new(3) { Hide::SecretKey.generate }
    begin
      box = Hide.encrypt("shared", recipients: keys.map(&:public_key))
      keys.each { |key| assert_equal "shared".b, Hide.decrypt(box, key).plaintext }
    ensure
      keys.each(&:close)
    end
  end

  def test_protected_keys_round_trip
    public_key = nil
    sealed = nil
    Hide::SecretKey.generate do |secret|
      public_key = secret.public_key
      sealed = secret.protect("correct horse battery")
    end

    assert_equal "protected", Hide.inspect_key(sealed)

    assert_raises(Hide::WrongPassphraseError) { Hide::SecretKey.open(sealed, "wrong passphrase") }
    assert_raises(Hide::WrongPassphraseError) { Hide::SecretKey.open(sealed) }

    Hide::SecretKey.open(sealed, "correct horse battery") do |reopened|
      assert_equal public_key, reopened.public_key
    end
  end

  def test_a_short_passphrase_is_refused
    Hide::SecretKey.generate do |secret|
      # The message proves this was refused here rather than by the core, so the
      # binding is not relying on a duplicate check it does not control.
      error = assert_raises(Hide::InvalidArgumentError) { secret.protect("short") }
      assert_match(/at least #{Hide::MIN_PASSPHRASE_LEN} characters/, error.message)
      assert_raises(Hide::InvalidArgumentError) { secret.protect("") }
      assert_equal 8, Hide::MIN_PASSPHRASE_LEN

      # The boundary itself is accepted.
      refute_empty secret.protect("a" * Hide::MIN_PASSPHRASE_LEN)
    end
  end

  def test_armor_round_trips
    Hide::SecretKey.generate do |secret|
      public_key = secret.public_key
      text = Hide.armor_public_key(public_key)
      assert text.start_with?("hide-public-key:"), text[0, 40].inspect
      assert_equal public_key, Hide.dearmor_public_key(text)
      assert_raises(Hide::Error) { Hide.dearmor_public_key("not a key") }
    end
  end

  def test_recipient_count_and_key_length_are_bounded
    Hide::SecretKey.generate do |secret|
      public_key = secret.public_key
      assert_raises(Hide::InvalidArgumentError) { Hide.encrypt("x", recipients: []) }
      assert_raises(Hide::InvalidArgumentError) do
        Hide.encrypt("x", recipients: Array.new(65) { public_key })
      end
      assert_raises(Hide::InvalidArgumentError) { Hide.encrypt("x", recipients: ["too short"]) }
      assert_raises(Hide::InvalidArgumentError) do
        Hide.encrypt("x", recipients: [public_key + "\x00".b])
      end

      # The upper bound itself is legal.
      box = Hide.encrypt("x", recipients: Array.new(64) { public_key })
      assert_equal "x".b, Hide.decrypt(box, secret).plaintext
    end
  end

  def test_a_closed_key_cannot_be_used_and_never_prints_key_material
    secret = Hide::SecretKey.generate
    public_key = secret.public_key

    assert_includes secret.inspect, "SecretKey"
    refute closed_key_leaks?(secret.inspect, public_key)
    refute closed_key_leaks?(secret.to_s, public_key)
    refute_includes secret.inspect, secret.object_id.to_s(16)

    secret.close
    secret.close # idempotent
    assert_predicate secret, :closed?
    assert_includes secret.inspect, "closed"

    assert_raises(Hide::ClosedKeyError) { secret.public_key }
    assert_raises(Hide::ClosedKeyError) { secret.protect("long enough passphrase") }
    assert_raises(Hide::ClosedKeyError) do
      Hide.decrypt(Hide.encrypt("x", recipients: [public_key]), secret)
    end
  end

  def test_a_block_always_closes_the_key_even_when_it_raises
    escaped = nil
    assert_raises(RuntimeError) do
      Hide::SecretKey.generate do |secret|
        escaped = secret
        raise "boom"
      end
    end
    assert_predicate escaped, :closed?
  end

  def test_empty_payloads_are_valid
    Hide::SecretKey.generate do |secret|
      box = Hide.encrypt("", recipients: [secret.public_key])
      assert_equal "", Hide.decrypt(box, secret).plaintext
    end
  end

  def test_metadata_is_absent_when_not_supplied
    Hide::SecretKey.generate do |secret|
      opened = Hide.decrypt(Hide.encrypt("x", recipients: [secret.public_key]), secret)
      assert_nil opened.filename
      assert_nil opened.media_type
    end
  end

  def test_metadata_survives_non_ascii_and_is_length_prefixed
    Hide::SecretKey.generate do |secret|
      # A NUL here would truncate under any C-string read; the core rejects it
      # up front, which is what proves we are not scanning for a terminator.
      name = "salariile lunii — ținută.csv"
      box = Hide.encrypt("x", recipients: [secret.public_key], filename: name)
      opened = Hide.decrypt(box, secret)
      assert_equal name, opened.filename
      assert_equal Encoding::UTF_8, opened.filename.encoding
      assert_raises(Hide::InvalidArgumentError) do
        Hide.encrypt("x", recipients: [secret.public_key], filename: "a\x00b")
      end
    end
  end

  def test_garbage_input_is_rejected_rather_than_crashing
    Hide::SecretKey.generate do |secret|
      [
        "",
        "\x00",
        "not a container at all",
        Random.bytes(2048),
        "\xFF".b * 5000
      ].each do |junk|
        assert_raises(Hide::Error) { Hide.decrypt(junk, secret) }
      end

      assert_raises(Hide::Error) { Hide::SecretKey.open("") }
      assert_raises(Hide::Error) { Hide::SecretKey.open(Random.bytes(64)) }
      assert_raises(Hide::Error) { Hide.armor_public_key("short") }
      assert_raises(Hide::Error) { Hide.armor_public_key("") }
      assert_raises(TypeError) { Hide.decrypt("x", :not_a_key) }

      # inspect_key sniffs a format rather than validating one, so unrecognised
      # bytes are reported as raw instead of raising; opening them is what fails.
      assert_equal "raw", Hide.inspect_key("nonsense")
    end
  end

  def test_binary_data_survives_untouched
    Hide::SecretKey.generate do |secret|
      payload = (0..255).to_a.pack("C*") * 40
      box = Hide.encrypt(payload, recipients: [secret.public_key])
      opened = Hide.decrypt(box, secret)
      assert_equal payload, opened.plaintext
      # A UTF-8 assumption anywhere in the path would corrupt these bytes.
      assert_equal Encoding::BINARY, opened.plaintext.encoding

      # A UTF-8 String in must come back byte-identical, not re-encoded.
      text = "ținută — ünïcode"
      round = Hide.decrypt(Hide.encrypt(text, recipients: [secret.public_key]), secret)
      assert_equal text.b, round.plaintext
      assert_equal text, round.plaintext.dup.force_encoding(Encoding::UTF_8)
    end
  end

  def test_a_protected_key_still_decrypts_after_reopening
    sealed = nil
    box = nil
    Hide::SecretKey.generate do |secret|
      sealed = secret.protect("a long enough passphrase")
      box = Hide.encrypt("through disk", recipients: [secret.public_key])
    end
    Hide::SecretKey.open(sealed, "a long enough passphrase") do |reopened|
      assert_equal "through disk".b, Hide.decrypt(box, reopened).plaintext
    end
  end

  def test_raw_keys_are_reported_as_raw
    Hide::SecretKey.generate do |secret|
      assert_equal "raw", Hide.inspect_key(Hide.dearmor_public_key(
                                             Hide.armor_public_key(secret.public_key)
                                           ))
    end
  end

  def test_version_is_reported
    refute_empty Hide.version
    assert_match(/\A\d+\.\d+/, Hide.version)
  end

  PASSPHRASE = "correct horse battery staple"
  CONTEXT = "HIDE/0.5 ruby test"

  def test_signs_and_verifies
    identity do |signer|
      public_key = signer.public_key
      assert_equal Hide::VERIFYING_KEY_LEN, public_key.bytesize
      assert_equal Encoding::BINARY, public_key.encoding

      signature = signer.sign(CONTEXT, "the message")
      assert_equal Hide::SIGNATURE_LEN, signature.bytesize
      assert_nil Hide.verify(public_key, CONTEXT, "the message", signature)
    end
  end

  def test_a_changed_message_does_not_verify
    identity do |signer|
      signature = signer.sign(CONTEXT, "the message")
      assert_raises(Hide::AuthenticationError) do
        Hide.verify(signer.public_key, CONTEXT, "the messagE", signature)
      end
    end
  end

  def test_a_different_context_does_not_verify
    identity do |signer|
      signature = signer.sign(CONTEXT, "the message")
      assert_raises(Hide::AuthenticationError) do
        Hide.verify(signer.public_key, "another context", "the message", signature)
      end
    end
  end

  def test_another_identity_cannot_be_impersonated
    identity do |signer|
      identity do |impostor|
        signature = impostor.sign(CONTEXT, "the message")
        assert_raises(Hide::AuthenticationError) do
          Hide.verify(signer.public_key, CONTEXT, "the message", signature)
        end
      end
    end
  end

  def test_an_encryption_only_key_cannot_sign
    sealed = nil
    Hide::SecretKey.generate { |secret| sealed = secret.protect(PASSPHRASE) }
    assert_raises(Hide::NotAKeyError) { Hide::SigningIdentity.load(sealed, PASSPHRASE) }
  end

  def test_a_challenge_is_answered_once_and_then_refused
    identity do |prover|
      public_key = prover.public_key
      challenge = Hide.new_challenge("ssh://host.example", 1_000, 60)
      answer = prover.answer(challenge)

      Hide::SpentNonces.open do |spent|
        assert_nil spent.accept(challenge, answer, public_key, 1_000)
        # The identical valid answer, presented again.
        assert_raises(Hide::ChallengeReplayedError) do
          spent.accept(challenge, answer, public_key, 1_000)
        end
      end
    end
  end

  def test_an_answer_after_the_window_is_refused
    identity do |prover|
      challenge = Hide.new_challenge("ssh://host.example", 1_000, 60)
      answer = prover.answer(challenge)
      Hide::SpentNonces.open do |spent|
        assert_raises(Hide::ChallengeExpiredError) do
          spent.accept(challenge, answer, prover.public_key, 1_100)
        end
      end
    end
  end

  def test_a_closed_identity_never_prints_key_material
    signer = Hide::SigningIdentity.load(
      Hide::SigningIdentity.generate(PASSPHRASE), PASSPHRASE
    )
    public_key = signer.public_key
    refute closed_key_leaks?(signer.inspect, public_key)

    signer.close
    signer.close # idempotent
    assert_predicate signer, :closed?
    assert_raises(Hide::ClosedKeyError) { signer.public_key }
    assert_raises(Hide::ClosedKeyError) { signer.sign(CONTEXT, "x") }
  end

  private

  def identity(&block)
    Hide::SigningIdentity.load(
      Hide::SigningIdentity.generate(PASSPHRASE), PASSPHRASE, &block
    )
  end

  def closed_key_leaks?(text, public_key)
    text.include?(public_key.unpack1("H*")[0, 16])
  end
end
