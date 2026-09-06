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
  MIN_PASSPHRASE_LEN = Binding::MIN_PASSPHRASE_LEN

  MAX_RECIPIENTS = 64

  # Base class for every failure this library reports.
  class Error < StandardError; end

  # An argument this library refused before it reached the core.
  class InvalidArgumentError < Error; end

  # The data was altered, or is not a HIDE container.
  class AuthenticationError < Error; end

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

  ERRORS = {
    Binding::ERR_INVALID_ARGUMENT => InvalidArgumentError,
    Binding::ERR_WRONG_PASSPHRASE => WrongPassphraseError,
    Binding::ERR_NOT_A_KEY => NotAKeyError,
    Binding::ERR_AUTHENTICATION => AuthenticationError,
    Binding::ERR_NO_MATCHING_RECIPIENT => NoMatchingRecipientError,
    Binding::ERR_MALFORMED => AuthenticationError,
    Binding::ERR_TOO_LARGE => TooLargeError
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
