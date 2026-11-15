# frozen_string_literal: true

# Exercises the Ruby SDK against the real native library.

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "minitest/autorun"
require "fileutils"
require "open3"
require "rbconfig"
require "tmpdir"
require "hide_protocol"
require_relative "fixtures"

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
  CONTEXT = "example/ruby test"

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

  # Spec §15.2: the generic API must not mint protocol signatures.
  def test_reserved_protocol_contexts_are_refused
    identity do |signer|
      ["HIDE/0.6 identity entry", "HIDE/1.0 container", "HIDE/"].each do |context|
        assert_raises(Hide::InvalidArgumentError) { signer.sign(context, "the message") }
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

      Hide::SpentNonces.open("ssh://host.example") do |spent|
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
      Hide::SpentNonces.open("ssh://host.example") do |spent|
        assert_raises(Hide::ChallengeExpiredError) do
          spent.accept(challenge, answer, prover.public_key, 1_100)
        end
      end
    end
  end

  # The record knows which service it answers for, so a challenge relayed from
  # elsewhere is refused even though the answer is a genuine signature that
  # would verify on its own.
  def test_an_answer_for_another_audience_is_refused
    identity do |prover|
      public_key = prover.public_key
      relayed = Hide.new_challenge("https://elsewhere.test", 1_000, 60)
      answer = prover.answer(relayed)

      Hide::SpentNonces.open("https://example.test") do |spent|
        assert_raises(Hide::ChallengeAudienceError) do
          spent.accept(relayed, answer, public_key, 1_010)
        end

        # The audience this record does answer to is unaffected.
        ours = Hide.new_challenge("https://example.test", 1_000, 60)
        assert_nil spent.accept(ours, prover.answer(ours), public_key, 1_010)
      end
    end
  end

  # Failing closed: a verifier that forgot to name its audience refuses every
  # answer rather than accepting one minted for anyone.
  def test_a_record_built_with_an_empty_audience_accepts_nothing
    identity do |prover|
      public_key = prover.public_key
      challenge = Hide.new_challenge("https://example.test", 1_000, 60)
      Hide::SpentNonces.open("") do |spent|
        assert_raises(Hide::ChallengeAudienceError) do
          spent.accept(challenge, prover.answer(challenge), public_key, 1_010)
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

  def test_an_identity_log_reports_the_devices_it_trusts
    # Four events: create, enrol phone, enrol laptop, revoke laptop.
    assert_equal 2, Hide.verify_identity(Fixtures::IDENTITY_LOG, Fixtures::IDENTITY_RECOVERY)
  end

  def test_a_revoked_device_is_no_longer_trusted
    assert Hide.identity_trusts_device(
      Fixtures::IDENTITY_LOG, Fixtures::IDENTITY_RECOVERY, Fixtures::IDENTITY_DEVICE_PHONE
    )
    refute Hide.identity_trusts_device(
      Fixtures::IDENTITY_LOG, Fixtures::IDENTITY_RECOVERY, Fixtures::IDENTITY_DEVICE_LAPTOP
    )
  end

  def test_a_tampered_log_is_refused
    assert_raises(Hide::AuthenticationError) do
      Hide.verify_identity(Fixtures::IDENTITY_TAMPERED, Fixtures::IDENTITY_RECOVERY)
    end
    # Bytes that do not decode at all are a different failure from bytes that
    # decode and do not verify.
    assert_raises(Hide::MalformedError) do
      Hide.verify_identity("not a log", Fixtures::IDENTITY_RECOVERY)
    end
  end

  def test_the_head_names_this_exact_history
    head = Hide.identity_head(Fixtures::IDENTITY_LOG, Fixtures::IDENTITY_RECOVERY)
    assert_equal Fixtures::IDENTITY_HEAD, head
    assert_equal 32, head.bytesize
  end

  def test_an_epoch_chain_verifies_and_yields_keys
    assert_equal 3, Hide.verify_epoch_chain(Fixtures::EPOCH_CHAIN)
    assert_equal Fixtures::EPOCH_PUBLIC_KEY_1, Hide.epoch_public_key(Fixtures::EPOCH_CHAIN, 1)
  end

  def test_an_epoch_beyond_the_chain_is_refused
    assert_raises(Hide::InvalidArgumentError) do
      Hide.epoch_public_key(Fixtures::EPOCH_CHAIN, 3)
    end
  end

  def test_a_spliced_epoch_chain_does_not_verify
    assert_raises(Hide::AuthenticationError) do
      Hide.verify_epoch_chain(Fixtures::EPOCH_BROKEN)
    end
  end

  def test_an_inclusion_proof_verifies_only_for_its_own_leaf
    assert_nil Hide.verify_inclusion(
      Fixtures::LEAF, 3, 8, Fixtures::INCLUSION_PATH, Fixtures::TREE_ROOT
    )
    assert_raises(Hide::AuthenticationError) do
      Hide.verify_inclusion(
        Fixtures::OTHER_LEAF, 3, 8, Fixtures::INCLUSION_PATH, Fixtures::TREE_ROOT
      )
    end
  end

  def test_a_path_that_is_not_whole_hashes_is_refused
    assert_raises(Hide::InvalidArgumentError) do
      Hide.verify_inclusion(
        Fixtures::LEAF, 3, 8, Fixtures::INCLUSION_PATH[0...-1], Fixtures::TREE_ROOT
      )
    end
  end

  def test_a_consistency_proof_catches_a_rewritten_history
    assert_nil Hide.verify_consistency(
      5, 8, Fixtures::CONSISTENCY_PATH, Fixtures::ROOT_AT_5, Fixtures::TREE_ROOT
    )
    # Same size, one entry silently replaced.
    assert_raises(Hide::AuthenticationError) do
      Hide.verify_consistency(
        5, 8, Fixtures::CONSISTENCY_PATH, Fixtures::ROOT_AT_5, Fixtures::REWRITTEN_ROOT
      )
    end
  end

  def test_a_pinned_identity_verifies_against_its_root
    assert_equal 2, Hide.verify_identity_pinned(
      Fixtures::BINDING_IDENTITY_LOG, Fixtures::BINDING_RECOVERY, Fixtures::BINDING_ROOT
    )
  end

  def test_a_hijacked_log_is_refused_even_with_a_forged_recovery_binding
    assert_forgery do
      Hide.verify_identity_pinned(
        Fixtures::BINDING_HIJACKED_LOG, Fixtures::BINDING_RECOVERY, Fixtures::BINDING_ROOT
      )
    end
    assert_forgery do
      Hide.verify_identity_pinned(
        Fixtures::BINDING_HIJACKED_LOG, Fixtures::BINDING_RECOVERY_FORGED, Fixtures::BINDING_ROOT
      )
    end
  end

  def test_a_log_under_another_root_is_refused
    assert_forgery do
      Hide.verify_identity_pinned(
        Fixtures::BINDING_IDENTITY_LOG, Fixtures::BINDING_RECOVERY, "\x00".b * 32
      )
    end
  end

  def test_a_truncated_recovery_binding_is_malformed
    assert_raises(Hide::MalformedError) do
      Hide.verify_identity_pinned(
        Fixtures::BINDING_IDENTITY_LOG, Fixtures::BINDING_RECOVERY[0, 100], Fixtures::BINDING_ROOT
      )
    end
  end

  def test_an_epoch_chain_bound_to_the_identity_verifies
    assert_equal 3, Hide.verify_epoch_chain_bound(
      Fixtures::BINDING_IDENTITY_LOG, Fixtures::BINDING_RECOVERY, Fixtures::BINDING_ROOT,
      Fixtures::EPOCH_CHAIN, Fixtures::BINDING_EPOCH
    )
  end

  def test_an_epoch_chain_bound_by_a_stranger_is_refused
    assert_forgery do
      Hide.verify_epoch_chain_bound(
        Fixtures::BINDING_IDENTITY_LOG, Fixtures::BINDING_RECOVERY, Fixtures::BINDING_ROOT,
        Fixtures::EPOCH_CHAIN, Fixtures::BINDING_EPOCH_STRANGER
      )
    end
  end

  def test_a_checkpoint_verifies_and_yields_size_and_root
    size, root = Hide.verify_checkpoint(
      Fixtures::CHECKPOINT_3, "log.example/hide", Fixtures::CHECKPOINT_LOG_KEY
    )
    assert_equal 3, size
    assert_equal 32, root.bytesize
    assert_equal Encoding::BINARY, root.encoding
  end

  def test_a_checkpoint_is_refused_when_altered_misattributed_or_mis_keyed
    assert_forgery do
      Hide.verify_checkpoint(
        Fixtures::CHECKPOINT_TAMPERED, "log.example/hide", Fixtures::CHECKPOINT_LOG_KEY
      )
    end
    assert_forgery do
      Hide.verify_checkpoint(Fixtures::CHECKPOINT_3, "other.example", Fixtures::CHECKPOINT_LOG_KEY)
    end
    assert_forgery do
      Hide.verify_checkpoint(
        Fixtures::CHECKPOINT_3, "log.example/hide", Fixtures::CHECKPOINT_WITNESS_KEY
      )
    end
  end

  # --- copies -------------------------------------------------------------

  # A copy would hold the same native pointer, and whichever of the two was
  # closed first would free it under the other.
  def test_a_handle_cannot_be_copied_or_serialized
    handles = [Hide::SecretKey.generate, identity, Hide::SpentNonces.new("ssh://host.example")]
    handles.each do |handle|
      error = assert_raises(TypeError, "#{handle.class}#dup") { handle.dup }
      assert_match(/cannot be copied/, error.message)
      assert_raises(TypeError, "#{handle.class}#clone") { handle.clone }
      assert_raises(TypeError, "#{handle.class}#clone(freeze: false)") { handle.clone(freeze: false) }
      assert_raises(TypeError, "Marshal.dump(#{handle.class})") { Marshal.dump(handle) }
      refute_predicate handle, :closed?
    end
  ensure
    handles&.each(&:close)
  end

  def test_the_original_still_works_after_a_refused_copy
    Hide::SecretKey.generate do |secret|
      assert_raises(TypeError) { secret.dup }
      box = Hide.encrypt("still here", recipients: [secret.public_key])
      assert_equal "still here".b, Hide.decrypt(box, secret).plaintext
    end
  end

  # Wrapping a raw address would make a second owner of someone else's pointer,
  # or an owner of an arbitrary one.
  def test_a_key_cannot_be_built_from_a_raw_address
    assert_raises(NoMethodError) { Hide::SecretKey.new(0x1000) }
    assert_raises(NoMethodError) { Hide::SigningIdentity.new(0x1000) }
    # The constructors the library itself uses still work.
    Hide::SecretKey.generate { |secret| refute_predicate secret, :closed? }
    identity { |signer| refute_predicate signer, :closed? }
  end

  # --- the empty buffer ----------------------------------------------------

  # hide_buffer_empty returns a 24-byte struct by value. Declared to fiddle as
  # a function taking one pointer it only worked where the ABI passes the
  # result address as a first argument, which arm64 does not. The binding now
  # zero-fills the slot itself and never calls it.
  def test_an_empty_buffer_is_zeroed_here_and_the_struct_return_is_not_bound
    refute Hide::Binding::SIGNATURES.key?(:hide_buffer_empty)
    refute Hide::Binding::FUNCTIONS.key?(:hide_buffer_empty)

    slot = Hide::Binding.empty_buffer
    assert_equal "\x00".b * Hide::Binding::BUFFER_SIZE, slot[0, Hide::Binding::BUFFER_SIZE]
    # Freeing an empty buffer is a no-op in the core, and yields no bytes here.
    assert_equal "".b, Hide::Binding.take(slot)
  end

  # --- threads -------------------------------------------------------------

  # fiddle releases the interpreter lock during a native call and the native
  # record is not synchronised, so the per-object lock is what makes sharing a
  # record safe. Holding it here must hold back a call made on another thread.
  def test_accept_holds_the_record_lock_for_the_native_call
    identity do |prover|
      public_key = prover.public_key
      challenge = Hide.new_challenge("ssh://host.example", 1_000, 60)
      answer = prover.answer(challenge)

      Hide::SpentNonces.open("ssh://host.example") do |spent|
        lock = spent.instance_variable_get(:@lock)
        assert_instance_of Thread::Mutex, lock

        finished = Queue.new
        worker = nil
        lock.synchronize do
          worker = Thread.new do
            spent.accept(challenge, answer, public_key, 1_000)
            finished << true
          end
          sleep 0.3
          assert_predicate finished, :empty?, "accept ran without taking the lock"
        end
        worker.join(30)
        refute_predicate finished, :empty?
        assert_raises(Hide::ChallengeReplayedError) do
          spent.accept(challenge, answer, public_key, 1_000)
        end
      end
    end
  end

  # Before the lock, a run of this size ended with a dozen or more replays
  # accepted: two threads pushing at once lost entries from the record.
  def test_one_record_shared_between_threads_accepts_each_answer_once
    identity do |prover|
      public_key = prover.public_key
      work = Array.new(8) do
        Array.new(60) do
          challenge = Hide.new_challenge("ssh://host.example", 1_000, 60)
          [challenge, prover.answer(challenge)]
        end
      end

      Hide::SpentNonces.open("ssh://host.example") do |spent|
        failures = Queue.new
        start = Queue.new
        threads = work.map do |answers|
          Thread.new do
            start.pop
            answers.each do |challenge, answer|
              spent.accept(challenge, answer, public_key, 1_000)
            rescue StandardError => e
              failures << e
            end
          end
        end
        work.length.times { start << true }
        threads.each { |thread| thread.join(120) }
        assert_predicate failures, :empty?

        replays_accepted = work.flatten(1).count do |challenge, answer|
          spent.accept(challenge, answer, public_key, 1_000)
          true
        rescue Hide::ChallengeReplayedError
          false
        end
        assert_equal 0, replays_accepted
      end
    end
  end

  # --- text that becomes a C string ----------------------------------------

  # A passphrase that is long enough on its own, then a NUL and more: a C
  # string read stops at the NUL, so the core would see only the first part.
  SPLIT = "longenough\x00rest"

  def test_a_passphrase_with_an_embedded_nul_is_refused_not_truncated
    sealed = nil
    Hide::SecretKey.generate do |secret|
      error = assert_raises(Hide::InvalidArgumentError) { secret.protect(SPLIT) }
      assert_match(/NUL/, error.message)
      sealed = secret.protect("longenough")
    end
    # Opening must refuse too: accepting it here would mean the text before
    # the NUL is what unlocks the key.
    assert_raises(Hide::InvalidArgumentError) { Hide::SecretKey.open(sealed, SPLIT) }

    assert_raises(Hide::InvalidArgumentError) { Hide::SigningIdentity.generate(SPLIT) }
    sealed_identity = Hide::SigningIdentity.generate("longenough")
    assert_raises(Hide::InvalidArgumentError) { Hide::SigningIdentity.open(sealed_identity, SPLIT) }
    # The same file still opens under the passphrase it was sealed with.
    Hide::SigningIdentity.open(sealed_identity, "longenough") { |signer| refute_predicate signer, :closed? }
  end

  def test_every_other_text_argument_refuses_an_embedded_nul
    Hide::SecretKey.generate do |secret|
      public_key = secret.public_key
      assert_raises(Hide::InvalidArgumentError) do
        Hide.encrypt("x", recipients: [public_key], filename: "report.txt\x00.exe")
      end
      assert_raises(Hide::InvalidArgumentError) do
        Hide.encrypt("x", recipients: [public_key], media_type: "text/plain\x00x")
      end
      assert_raises(Hide::InvalidArgumentError) do
        Hide.dearmor_public_key("#{Hide.armor_public_key(public_key)}\x00trailing")
      end
    end
    assert_raises(Hide::InvalidArgumentError) do
      Hide.new_challenge("app.example\x00.evil.example", 1_000, 60)
    end
    assert_raises(Hide::InvalidArgumentError) do
      Hide::SpentNonces.new("app.example\x00.evil.example")
    end
    assert_raises(Hide::InvalidArgumentError) do
      Hide.verify_checkpoint("note", "log.example\x00/hide", "key")
    end
  end

  def test_a_non_ascii_passphrase_still_round_trips
    passphrase = "parolă lungă — ținută"
    sealed = Hide::SecretKey.generate { |secret| secret.protect(passphrase) }
    Hide::SecretKey.open(sealed, passphrase) { |reopened| refute_predicate reopened, :closed? }
    # The same bytes tagged as binary are the same passphrase.
    Hide::SecretKey.open(sealed, passphrase.b) { |reopened| refute_predicate reopened, :closed? }
    # So is the same text in another encoding. UTF-16 is full of NUL bytes:
    # sent as it stands it would be cut short at the first one.
    Hide::SecretKey.open(sealed, passphrase.encode(Encoding::UTF_16LE)) do |reopened|
      refute_predicate reopened, :closed?
    end
  end

  def test_a_filename_that_is_not_one_portable_file_name_is_refused
    Hide::SecretKey.generate do |secret|
      public_key = secret.public_key
      ["a/b", "a\\b", "..", "CON", "com1.txt", "trailing.", "trailing ", "tab\there",
       "what?.txt", "x" * 256].each do |filename|
        assert_raises(Hide::Error, filename.inspect) do
          Hide.encrypt("x", recipients: [public_key], filename: filename)
        end
      end
      ["report.txt", "CONSOLE.txt", "x" * 255].each do |filename|
        box = Hide.encrypt("x", recipients: [public_key], filename: filename)
        assert_equal filename, Hide.decrypt(box, secret).filename
      end
    end
  end

  # The calls only read the native object, so no lock is involved.
  def test_one_key_and_one_identity_serve_several_threads
    Hide::SecretKey.generate do |secret|
      identity do |signer|
        public_key = secret.public_key
        verifying = signer.public_key
        box = Hide.encrypt("shared", recipients: [public_key])
        failures = Queue.new
        threads = Array.new(6) do |index|
          Thread.new do
            5.times do |round|
              message = "#{index}/#{round}"
              signature = signer.sign("example/threads", message)
              Hide.verify(verifying, "example/threads", message, signature)
              raise "wrong plaintext" unless Hide.decrypt(box, secret).plaintext == "shared".b
              raise "wrong public key" unless secret.public_key == public_key
            end
          rescue StandardError => e
            failures << e
          end
        end
        threads.each { |thread| thread.join(120) }
        assert_predicate failures, :empty?
      end
    end
  end

  # --- how the native library is found -------------------------------------

  LIB_DIR = File.expand_path("../lib", __dir__)
  GEMSPEC = File.expand_path("../hide-protocol.gemspec", __dir__)
  NO_OVERRIDE = { "HIDE_LIBRARY" => nil, "HIDE_ALLOW_LIBRARY_OVERRIDE" => nil }.freeze

  # Reports what was loaded, and every name handed to the system loader.
  PROBE = <<~'RUBY'
    require "fiddle"
    asked = []
    Fiddle.singleton_class.prepend(Module.new do
      define_method(:dlopen) do |name|
        asked << name
        super(name)
      end
    end)
    begin
      require "hide_protocol"
      puts "LOADED #{Hide::Binding::LIBRARY_PATH}"
    rescue Hide::Binding::LibraryNotFound, Hide::Binding::VersionMismatch => e
      puts "NOTFOUND #{e.message}"
    end
    asked.each { |name| puts "ASKED #{name}" }
  RUBY

  def test_the_library_is_loaded_by_absolute_path
    path = Hide::Binding::LIBRARY_PATH
    assert File.absolute_path?(path), path
    assert File.file?(path), path
  end

  # The layout a platform gem installs: the core beside binding.rb. The working
  # tree never contains the library, so this is the only way to exercise it.
  def test_the_bundled_library_is_found_with_nothing_set
    with_installed_gem do |lib|
      output = probe(NO_OVERRIDE, lib: lib)
      expected = File.join(lib, "hide_protocol", Hide::Binding.library_names.first)
      assert_equal "LOADED #{expected}", output.lines.first.chomp
    end
  end

  # The copied binding says 0.0.1; the core beside it is the one under test.
  def test_a_core_from_another_release_is_refused_when_the_gem_loads
    with_installed_gem(version: "0.0.1") do |lib|
      first = probe(NO_OVERRIDE, lib: lib).lines.first.chomp
      assert_match(/\ANOTFOUND the HIDE native library is version /, first)
      assert_includes first, "this binding is 0.0.1"
      assert_includes first, "install matching versions"
    end
  end

  # The library is chosen once, when the file is required, so only a new
  # process can show how a different environment is treated.
  def test_the_system_loader_is_never_asked_to_search_by_name
    Dir.mktmpdir("hide-planted-") do |planted|
      # A copy of the real core, so loading it would succeed if anything
      # searched for it: the working directory, PATH, and the search paths
      # the Unix loaders honour.
      FileUtils.cp(Hide::Binding::LIBRARY_PATH, File.join(planted, Hide::Binding.library_names.first))
      env = NO_OVERRIDE.merge(
        %w[PATH LD_LIBRARY_PATH DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH].to_h do |name|
          # In front of what is already there: the interpreter itself may
          # need the existing value to start.
          [name, [planted, ENV[name]].compact.reject(&:empty?).join(File::PATH_SEPARATOR)]
        end
      )
      output = probe(env, chdir: planted)

      asked = output.lines.grep(/\AASKED .*hide_ffi/).map { |line| line.sub("ASKED ", "").chomp }
      asked.each { |name| assert File.absolute_path?(name), "the loader was asked for #{name.inspect}" }
      refute_includes output, File.basename(planted)
      assert_packaged_or_not_found(output)
    end
  end

  # One settable variable must not be enough to replace the core. The path
  # does not exist, so honouring it could only show up as a failure naming it.
  def test_hide_library_alone_is_ignored
    [nil, "0", "true", "yes", " 1"].each do |opt_in|
      output = probe({ "HIDE_LIBRARY" => absent_library, "HIDE_ALLOW_LIBRARY_OVERRIDE" => opt_in })
      refute_includes output, "no-such-directory", "opt-in #{opt_in.inspect}"
      assert_packaged_or_not_found(output)
    end
  end

  def test_hide_library_with_the_opt_in_is_what_gets_loaded
    output = probe({ "HIDE_LIBRARY" => absent_library, "HIDE_ALLOW_LIBRARY_OVERRIDE" => "1" })
    # It is tried, and a failure says so rather than falling back to another copy.
    assert_match(/\ANOTFOUND /, output)
    assert_includes output, "no-such-directory"
    assert_includes output, "could not be loaded"

    real = Hide::Binding::LIBRARY_PATH
    output = probe({ "HIDE_LIBRARY" => real, "HIDE_ALLOW_LIBRARY_OVERRIDE" => "1" })
    assert_equal "LOADED #{real}", output.lines.first.chomp
  end

  # --- the core and the binding are the same release -----------------------

  def test_the_loaded_core_is_this_bindings_version
    assert_equal Hide::Binding::BINDING_VERSION.split(".").first(3), Hide.version.split(".").first(3)
    assert_nil Hide::Binding.check_version(Hide.version)
  end

  def test_matching_versions_are_accepted
    [%w[0.9.1 0.9.1], %w[1.2.3 1.2.3], %w[0.10.0-rc.1 0.10.0], %w[0.10.0 0.10.0+build.7]].each do |core, binding|
      assert_nil Hide::Binding.check_version(core, binding)
    end
  end

  def test_a_core_of_another_version_is_refused
    [
      %w[0.9.0 0.9.1],  # a stale core beside a newer binding
      %w[0.9.2 0.9.1],  # and the reverse
      %w[0.10.1 0.9.1],
      %w[1.9.1 0.9.1],
      %w[0.9.10 0.9.1], # compared as numbers, not as a text prefix
      %w[0.91.0 0.9.10]
    ].each do |core, binding|
      error = assert_raises(Hide::Binding::VersionMismatch, "#{core} vs #{binding}") do
        Hide::Binding.check_version(core, binding)
      end
      assert_match(/install matching versions/, error.message)
    end
  end

  def test_a_core_that_does_not_state_a_version_is_refused
    ["", "0.9", "v0.9.1", "latest"].each do |core|
      assert_raises(Hide::Binding::VersionMismatch, core.inspect) do
        Hide::Binding.check_version(core, "0.9.1")
      end
    end
  end

  # --- packaging -----------------------------------------------------------

  # fiddle stops being a default gem in Ruby 4.0, so without a declared
  # dependency a Bundler-managed application cannot require it.
  def test_the_gem_declares_its_dependency_on_fiddle
    spec = Gem::Specification.load(File.expand_path("../hide-protocol.gemspec", __dir__))
    fiddle = spec.runtime_dependencies.find { |dependency| dependency.name == "fiddle" }
    refute_nil fiddle, "no runtime dependency on fiddle"
    assert fiddle.requirement.satisfied_by?(Gem::Version.new(Fiddle::VERSION))
    assert_equal Hide::Binding::BINDING_VERSION, spec.version.to_s
  end

  private

  def probe(env, chdir: Dir.pwd, lib: LIB_DIR)
    output, status = Open3.capture2e(env, RbConfig.ruby, "-I", lib, "-e", PROBE, chdir: chdir)
    assert_predicate status, :success?, output
    output
  end

  # Copies the gem's files the way an installed gem lays them out, with the
  # core bundled beside binding.rb, and yields its lib directory.
  def with_installed_gem(version: nil)
    Dir.mktmpdir("hide-gem-") do |root|
      root = File.realpath(root)
      lib = File.join(root, "lib")
      FileUtils.mkdir_p(File.join(lib, "hide_protocol"))
      FileUtils.cp(File.join(LIB_DIR, "hide_protocol.rb"), lib)
      FileUtils.cp(File.join(LIB_DIR, "hide_protocol", "binding.rb"), File.join(lib, "hide_protocol"))
      FileUtils.cp(
        Hide::Binding::LIBRARY_PATH,
        File.join(lib, "hide_protocol", Hide::Binding.library_names.first)
      )
      gemspec = File.read(GEMSPEC, encoding: "UTF-8")
      if version
        current = %(spec.version = "#{Hide::Binding::BINDING_VERSION}")
        assert_includes gemspec, current
        gemspec = gemspec.sub(current, %(spec.version = "#{version}"))
      end
      File.write(File.join(root, "hide-protocol.gemspec"), gemspec, encoding: "UTF-8")
      yield lib
    end
  end

  def absent_library
    File.join(Dir.tmpdir, "no-such-directory", "hide_ffi_override")
  end

  # With no override, either the copy shipped beside the binding loaded, or
  # nothing did and the error says what to install.
  def assert_packaged_or_not_found(output)
    first = output.lines.first.to_s.chomp
    if first.start_with?("LOADED ")
      assert_equal File.join(LIB_DIR, "hide_protocol"), File.dirname(first.sub("LOADED ", ""))
    else
      assert_match(/\ANOTFOUND .*was not found/, first)
      assert_includes first, RUBY_PLATFORM
    end
  end

  # Exactly AuthenticationError: a MalformedError here would mean the check
  # never got as far as verifying, and the test would pass for the wrong reason.
  def assert_forgery(&block)
    error = assert_raises(Hide::AuthenticationError, &block)
    assert_instance_of Hide::AuthenticationError, error
  end

  def identity(&block)
    Hide::SigningIdentity.load(
      Hide::SigningIdentity.generate(PASSPHRASE), PASSPHRASE, &block
    )
  end

  def closed_key_leaks?(text, public_key)
    text.include?(public_key.unpack1("H*")[0, 16])
  end
end
