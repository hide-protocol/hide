# frozen_string_literal: true

require_relative "hide_protocol/binding"

# HIDE — encrypt to a person, not to a key.
#
# EXPERIMENTAL AND UNAUDITED. Do not protect data you cannot afford to lose or
# expose. A successful decryption proves the data was not altered; it does
# *not* prove who created it.
#
#   secret = Hide::SecretKey.generate
#   box = Hide.encrypt("hello", recipients: [secret.public_key])
#   Hide.decrypt(box, secret).plaintext # => "hello"
module Hide
  PUBLIC_KEY_LEN = Binding::PUBLIC_KEY_LEN
  SIGNATURE_LEN = Binding::SIGNATURE_LEN
  VERIFYING_KEY_LEN = Binding::VERIFYING_KEY_LEN
  NONCE_LEN = Binding::NONCE_LEN
  MIN_PASSPHRASE_LEN = Binding::MIN_PASSPHRASE_LEN

  MAX_RECIPIENTS = 64

  # Base class for every failure this library reports.
  class Error < StandardError; end

  # An argument this library refused before it reached the core.
  class InvalidArgumentError < Error; end

  # The data was altered, or is not a HIDE container.
  class AuthenticationError < Error; end

  # The bytes did not decode at all.
  #
  # A subclass of AuthenticationError so that code which only cares that
  # something failed is unaffected, while a caller that must tell corruption
  # from forgery can rescue this specifically.
  class MalformedError < AuthenticationError; end

  # The passphrase is wrong, or the key file was modified.
  class WrongPassphraseError < Error; end

  # This key was not one of the recipients.
  class NoMatchingRecipientError < Error; end

  # The bytes are not a HIDE key.
  class NotAKeyError < Error; end

  # More data than the format admits.
  class TooLargeError < Error; end

  # The key has been closed and its material released.
  class ClosedKeyError < Error; end

  # The challenge expired before it was answered.
  class ChallengeExpiredError < Error; end

  # This challenge was already answered. Almost certainly a replay.
  class ChallengeReplayedError < Error; end

  ERRORS = {
    Binding::ERR_INVALID_ARGUMENT => InvalidArgumentError,
    Binding::ERR_WRONG_PASSPHRASE => WrongPassphraseError,
    Binding::ERR_NOT_A_KEY => NotAKeyError,
    Binding::ERR_AUTHENTICATION => AuthenticationError,
    Binding::ERR_NO_MATCHING_RECIPIENT => NoMatchingRecipientError,
    Binding::ERR_MALFORMED => MalformedError,
    Binding::ERR_TOO_LARGE => TooLargeError,
    Binding::ERR_CHALLENGE_EXPIRED => ChallengeExpiredError,
    Binding::ERR_CHALLENGE_REPLAYED => ChallengeReplayedError
  }.freeze

  class << self
    def version
      Binding.static_string(Binding.call(:hide_version))
    end

    # Encrypts for 1..64 recipient public keys. Returns binary bytes.
    def encrypt(plaintext, recipients:, filename: nil, media_type: nil)
      joined = join_recipients(recipients)
      plain = binary(plaintext, "plaintext")

      out = Binding.empty_buffer
      check(Binding.call(
              :hide_encrypt,
              buffer_arg(plain), plain.bytesize,
              joined, recipients.length,
              cstring(filename), cstring(media_type),
              out
            ))
      Binding.take(out)
    end

    # Decrypts and verifies. Nothing is returned unless the whole payload
    # authenticates, so a caller cannot act on unverified data.
    def decrypt(container, secret)
      raise TypeError, "secret must be a Hide::SecretKey" unless secret.is_a?(SecretKey)

      bytes = binary(container, "container")
      out = Binding.empty_buffer
      filename = Binding.empty_buffer
      media_type = Binding.empty_buffer
      begin
        check(Binding.call(
                :hide_decrypt,
                buffer_arg(bytes), bytes.bytesize,
                secret.__handle,
                out, filename, media_type
              ))
      rescue StandardError
        # On failure the core leaves the out-parameters untouched, so these are
        # still the empty buffers we created and freeing them is what releases
        # the scratch space.
        Binding.take(out)
        Binding.take(filename)
        Binding.take(media_type)
        raise
      end

      Decrypted.new(
        Binding.take(out),
        Binding.take_text(filename),
        Binding.take_text(media_type)
      )
    end

    # Renders a public key as pasteable text.
    def armor_public_key(public_key)
      bytes = binary(public_key, "public key")
      out = Binding.empty_buffer
      check(Binding.call(:hide_public_key_armor, buffer_arg(bytes), bytes.bytesize, out))
      Binding.take_text(out) || ""
    end

    def dearmor_public_key(text)
      out = Binding.empty_buffer
      check(Binding.call(:hide_public_key_dearmor, cstring(text.to_s), out))
      Binding.take(out)
    end

    # Returns "raw" or "protected" without needing the passphrase.
    def inspect_key(data)
      bytes = binary(data, "key")
      slot = Binding.pointer_slot
      check(Binding.call(:hide_inspect_key, buffer_arg(bytes), bytes.bytesize, slot))
      kind = slot[0, Binding::WORD].unpack1(Binding::WORD_PACK) & 0xFFFFFFFF
      kind == Binding::KEY_PROTECTED ? "protected" : "raw"
    end

    def sign(identity, context, message)
      identity.sign(context, message)
    end

    # Raises unless both the Ed25519 and the ML-DSA half verify. Nothing is
    # returned: a caller who forgot to test a boolean would read every failure
    # as a pass.
    def verify(public_key, context, message, signature)
      key = binary(public_key, "public key")
      ctx = binary(context, "context")
      msg = binary(message, "message")
      sig = binary(signature, "signature")
      check(Binding.call(
              :hide_verify_message,
              buffer_arg(key), key.bytesize,
              buffer_arg(ctx), ctx.bytesize,
              buffer_arg(msg), msg.bytesize,
              buffer_arg(sig), sig.bytesize
            ))
      nil
    end

    # A detached signature proves possession at some point, to nobody in
    # particular, and can be replayed. A challenge binds a random nonce, an
    # audience and an expiry, so an answer is good once, here, now.
    def new_challenge(audience, now, valid_for)
      out = Binding.empty_buffer
      check(Binding.call(
              :hide_challenge_new,
              cstring(audience), Integer(now), Integer(valid_for), out
            ))
      Binding.take(out)
    end

    # Replays an identity log and returns how many devices it trusts now.
    #
    # Raises MalformedError for a log that does not decode and
    # AuthenticationError for one that decodes but does not verify — the
    # distinction that tells corruption from forgery. A count is returned
    # rather than a boolean: a caller who forgot to test one would read every
    # failure as a pass.
    def verify_identity(log, recovery_key)
      bytes = binary(log, "log")
      recovery = binary(recovery_key, "recovery key")
      slot = Binding.pointer_slot
      check(Binding.call(
              :hide_identity_verify,
              buffer_arg(bytes), bytes.bytesize,
              buffer_arg(recovery), recovery.bytesize,
              slot
            ))
      Binding.read_count(slot)
    end

    # Whether the log trusts this device right now.
    #
    # A boolean is right here — this is a membership query, not a
    # cryptographic check. The log is still verified first, so false means
    # "not a member", never "did not verify": that raises.
    def identity_trusts_device(log, recovery_key, device_public_key)
      bytes = binary(log, "log")
      recovery = binary(recovery_key, "recovery key")
      device = binary(device_public_key, "device public key")
      slot = Binding.pointer_slot
      check(Binding.call(
              :hide_identity_trusts_device,
              buffer_arg(bytes), bytes.bytesize,
              buffer_arg(recovery), recovery.bytesize,
              buffer_arg(device), device.bytesize,
              slot
            ))
      (Binding.read_count(slot) & 0xFFFFFFFF) != 0
    end

    # The head link: 32 bytes naming this exact history.
    def identity_head(log, recovery_key)
      bytes = binary(log, "log")
      recovery = binary(recovery_key, "recovery key")
      out = Binding.empty_buffer
      check(Binding.call(
              :hide_identity_head,
              buffer_arg(bytes), bytes.bytesize,
              buffer_arg(recovery), recovery.bytesize,
              out
            ))
      Binding.take(out)
    end

    # Verifies a published epoch history and returns how many epochs it holds.
    def verify_epoch_chain(chain)
      bytes = binary(chain, "chain")
      slot = Binding.pointer_slot
      check(Binding.call(:hide_epoch_verify, buffer_arg(bytes), bytes.bytesize, slot))
      Binding.read_count(slot)
    end

    # The public key a sender should encrypt to for this epoch.
    #
    # The chain is verified first, so a key is never returned from a history
    # that does not hold together. An epoch beyond the chain raises
    # InvalidArgumentError.
    def epoch_public_key(chain, epoch)
      bytes = binary(chain, "chain")
      out = Binding.empty_buffer
      check(Binding.call(
              :hide_epoch_public_key,
              buffer_arg(bytes), bytes.bytesize, Integer(epoch), out
            ))
      Binding.take(out)
    end

    # Checks that leaf is entry index of a log of size entries under root.
    #
    # path is the concatenated 32-byte hashes; any other length raises
    # InvalidArgumentError. Nothing is returned, for the same reason verify
    # returns nothing.
    def verify_inclusion(leaf, index, size, path, root)
      leaf_bytes = binary(leaf, "leaf")
      path_bytes = binary(path, "path")
      root_bytes = binary(root, "root")
      check(Binding.call(
              :hide_transparency_verify_inclusion,
              buffer_arg(leaf_bytes), leaf_bytes.bytesize,
              Integer(index), Integer(size),
              buffer_arg(path_bytes), path_bytes.bytesize,
              buffer_arg(root_bytes), root_bytes.bytesize
            ))
      nil
    end

    # Checks that old_root really is the root the log had before it grew to
    # new_root. This is the check that catches a rewritten history.
    def verify_consistency(old_size, new_size, path, old_root, new_root)
      path_bytes = binary(path, "path")
      old_bytes = binary(old_root, "old root")
      new_bytes = binary(new_root, "new root")
      check(Binding.call(
              :hide_transparency_verify_consistency,
              Integer(old_size), Integer(new_size),
              buffer_arg(path_bytes), path_bytes.bytesize,
              buffer_arg(old_bytes), old_bytes.bytesize,
              buffer_arg(new_bytes), new_bytes.bytesize
            ))
      nil
    end

    def check(code)
      return if code == Binding::OK

      message = Binding.static_string(Binding.call(:hide_error_message, code))
      raise ERRORS.fetch(code, Error), message
    end

    private

    def join_recipients(recipients)
      unless recipients.is_a?(Array)
        raise InvalidArgumentError, "recipients must be an array of public keys"
      end
      unless recipients.length.between?(1, MAX_RECIPIENTS)
        raise InvalidArgumentError, "there must be between 1 and #{MAX_RECIPIENTS} recipients"
      end

      recipients.each_with_object(+"") do |key, acc|
        bytes = binary(key, "public key")
        if bytes.bytesize != PUBLIC_KEY_LEN
          raise InvalidArgumentError,
                "a public key is #{PUBLIC_KEY_LEN} bytes, got #{bytes.bytesize}"
        end
        acc << bytes
      end.force_encoding(Encoding::BINARY)
    end

    def binary(value, what)
      raise InvalidArgumentError, "#{what} must be a String" unless value.is_a?(String)

      value.dup.force_encoding(Encoding::BINARY)
    end

    # Fiddle passes a String as a pointer to its bytes, but a zero-length
    # String has no address the callee may read, so give it one it can ignore.
    def buffer_arg(bytes)
      bytes.empty? ? Fiddle::Pointer.malloc(1, Fiddle::RUBY_FREE) : bytes
    end

    # NULL for absent, UTF-8 plus a terminator otherwise.
    def cstring(value)
      return nil if value.nil?

      text = value.to_s
      if text.include?("\x00")
        raise InvalidArgumentError, "text passed to the core must not contain NUL"
      end

      "#{text.encode(Encoding::UTF_8)}\x00".force_encoding(Encoding::BINARY)
    end
  end

  # A verified payload. Holding one of these means it authenticated.
  #
  # The filename is attacker-controlled: never use it to choose an output path.
  class Decrypted
    attr_reader :plaintext, :filename, :media_type

    def initialize(plaintext, filename, media_type)
      @plaintext = plaintext
      @filename = filename
      @media_type = media_type
      freeze
    end

    alias data plaintext
  end

  # Argument coercion shared by the classes that pass byte strings to the core.
  module Bytes
    private

    def binary(value, what)
      raise InvalidArgumentError, "#{what} must be a String" unless value.is_a?(String)

      value.dup.force_encoding(Encoding::BINARY)
    end

    # Fiddle passes a String as a pointer to its bytes, but a zero-length
    # String has no address the callee may read, so give it one it can ignore.
    def arg(bytes)
      bytes.empty? ? Fiddle::Pointer.malloc(1, Fiddle::RUBY_FREE) : bytes
    end
  end

  # A signing key. The seed stays inside the native library and is never
  # exposed to Ruby; there is deliberately no accessor for it.
  class SigningIdentity
    include Bytes

    class << self
      # Creates an identity and returns the sealed key file to store. One seed
      # backs both encryption and signing, so there is one thing to back up.
      def generate(passphrase)
        text = passphrase.to_s
        if text.length < MIN_PASSPHRASE_LEN
          raise InvalidArgumentError,
                "the passphrase must be at least #{MIN_PASSPHRASE_LEN} characters"
        end

        out = Binding.empty_buffer
        Hide.check(Binding.call(:hide_identity_generate, "#{text}\x00".b, out))
        Binding.take(out)
      end

      # Loads a signing identity. A key file written before signatures existed
      # carries no signing seed and fails rather than being downgraded.
      def open(data, passphrase = nil, &block)
        raise InvalidArgumentError, "key data must be a String" unless data.is_a?(String)

        bytes = data.dup.force_encoding(Encoding::BINARY)
        handle = Binding.pointer_slot
        Hide.check(Binding.call(
                     :hide_signing_identity_open,
                     bytes.empty? ? Fiddle::Pointer.malloc(1, Fiddle::RUBY_FREE) : bytes,
                     bytes.bytesize,
                     passphrase.nil? ? nil : "#{passphrase}\x00".b,
                     handle
                   ))
        identity = new(handle[0, Binding::WORD].unpack1(Binding::WORD_PACK))
        return identity unless block

        begin
          block.call(identity)
        ensure
          identity.close
        end
      end

      alias load open
    end

    def initialize(address)
      @address = address
    end

    # The shareable verifying key, for others to check signatures with.
    def public_key
      alive!
      out = Binding.empty_buffer
      Hide.check(Binding.call(:hide_signing_identity_public, handle, out))
      Binding.take(out)
    end

    # context separates uses of one identity, so a signature made for one
    # purpose cannot be replayed as another. Never let a remote party choose it.
    def sign(context, message)
      alive!
      ctx = binary(context, "context")
      msg = binary(message, "message")
      out = Binding.empty_buffer
      Hide.check(Binding.call(
                   :hide_sign_message,
                   handle,
                   arg(ctx), ctx.bytesize,
                   arg(msg), msg.bytesize,
                   out
                 ))
      Binding.take(out)
    end

    # Answers a challenge, proving possession to whoever issued it.
    def answer(challenge)
      alive!
      bytes = binary(challenge, "challenge")
      out = Binding.empty_buffer
      Hide.check(Binding.call(:hide_challenge_answer, handle, arg(bytes), bytes.bytesize, out))
      Binding.take(out)
    end

    def close
      return if @address.nil? || @address.zero?

      Binding.call(:hide_signing_identity_free, Fiddle::Pointer.new(@address))
      @address = nil
      nil
    end

    def closed?
      @address.nil? || @address.zero?
    end

    # Never render key material, not even a fingerprint of it.
    def inspect
      "#<Hide::SigningIdentity #{closed? ? "closed" : "open"}>"
    end

    alias to_s inspect

    private

    def handle
      Fiddle::Pointer.new(@address)
    end

    def alive!
      raise ClosedKeyError, "this identity has been closed" if closed?
    end
  end

  # The verifier's record of answered challenges.
  #
  # Replay can only be detected by the verifier: a replayed answer is a genuine
  # signature and nothing about it is invalid on its own. This must therefore
  # outlive a single request.
  class SpentNonces
    include Bytes

    def self.open
      record = new
      return record unless block_given?

      begin
        yield record
      ensure
        record.close
      end
    end

    def initialize
      pointer = Binding.call(:hide_spent_nonces_new)
      raise Error, "could not allocate the nonce record" if pointer.null?

      @address = pointer.to_i
    end

    # Accepts an answer exactly once: raises ChallengeReplayedError the second
    # time, ChallengeExpiredError after the window, AuthenticationError if it
    # does not verify.
    def accept(challenge, signature, public_key, now)
      raise ClosedKeyError, "this record has been closed" if closed?

      chal = binary(challenge, "challenge")
      sig = binary(signature, "signature")
      key = binary(public_key, "public key")
      Hide.check(Binding.call(
                   :hide_challenge_accept,
                   Fiddle::Pointer.new(@address),
                   arg(chal), chal.bytesize,
                   arg(sig), sig.bytesize,
                   arg(key), key.bytesize,
                   Integer(now)
                 ))
      nil
    end

    def close
      return if closed?

      Binding.call(:hide_spent_nonces_free, Fiddle::Pointer.new(@address))
      @address = nil
      nil
    end

    def closed?
      @address.nil? || @address.zero?
    end
  end

  # A secret key. The bytes stay inside the native library and are never
  # exposed to Ruby; there is deliberately no accessor for them.
  class SecretKey
    class << self
      def generate(&block)
        handle = Binding.pointer_slot
        public_key = Binding.empty_buffer
        Hide.check(Binding.call(:hide_keypair_generate, handle, public_key))
        Binding.take(public_key)
        wrap(handle, &block)
      end

      # Loads a key file. A protected key without its passphrase fails.
      def open(data, passphrase = nil, &block)
        unless data.is_a?(String)
          raise InvalidArgumentError, "key data must be a String"
        end

        bytes = data.dup.force_encoding(Encoding::BINARY)
        handle = Binding.pointer_slot
        Hide.check(Binding.call(
                     :hide_secret_key_open,
                     bytes.empty? ? Fiddle::Pointer.malloc(1, Fiddle::RUBY_FREE) : bytes,
                     bytes.bytesize,
                     passphrase.nil? ? nil : "#{passphrase}\x00".b,
                     handle
                   ))
        wrap(handle, &block)
      end

      alias load open

      private

      # With a block the key is always closed, even if the block raises.
      def wrap(handle, &block)
        key = new(handle[0, Binding::WORD].unpack1(Binding::WORD_PACK))
        return key unless block

        begin
          block.call(key)
        ensure
          key.close
        end
      end
    end

    def initialize(address)
      @address = address
    end

    def public_key
      alive!
      out = Binding.empty_buffer
      Hide.check(Binding.call(:hide_secret_key_public, handle, out))
      Binding.take(out)
    end

    # Seals this key with a passphrase, for writing to disk. A forgotten
    # passphrase cannot be recovered: there is no escrow.
    def protect(passphrase)
      alive!
      text = passphrase.to_s
      if text.length < MIN_PASSPHRASE_LEN
        raise InvalidArgumentError,
              "the passphrase must be at least #{MIN_PASSPHRASE_LEN} characters"
      end

      out = Binding.empty_buffer
      Hide.check(Binding.call(:hide_secret_key_protect, handle, "#{text}\x00".b, out))
      Binding.take(out)
    end

    def close
      return if @address.nil? || @address.zero?

      Binding.call(:hide_secret_key_free, Fiddle::Pointer.new(@address))
      @address = nil
      nil
    end

    def closed?
      @address.nil? || @address.zero?
    end

    # Never render key material, not even a fingerprint of it.
    def inspect
      "#<Hide::SecretKey #{closed? ? "closed" : "open"}>"
    end

    alias to_s inspect

    # Internal: the raw handle, for Hide.decrypt.
    def __handle
      alive!
      handle
    end

    private

    def handle
      Fiddle::Pointer.new(@address)
    end

    def alive!
      raise ClosedKeyError, "this key has been closed" if closed?
    end
  end
end
