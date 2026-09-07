# frozen_string_literal: true

require "fiddle"
require "rbconfig"

module Hide
  # Raw access to the HIDE C core.
  #
  # fiddle rather than the ffi gem: fiddle ships with Ruby, so installing this
  # gem needs no compiler and adds no runtime dependency, and the ABI is
  # described in exactly one place.
  module Binding
    OK = 0
    ERR_INVALID_ARGUMENT = 1
    ERR_WRONG_PASSPHRASE = 2
    ERR_NOT_A_KEY = 3
    ERR_AUTHENTICATION = 4
    ERR_NO_MATCHING_RECIPIENT = 5
    ERR_TOO_LARGE = 7
    ERR_MALFORMED = 6
    ERR_CHALLENGE_EXPIRED = 8
    ERR_CHALLENGE_REPLAYED = 9
    ERR_PANIC = 98
    ERR_INTERNAL = 99

    KEY_RAW = 0
    KEY_PROTECTED = 1

    PUBLIC_KEY_LEN = 1216
    SIGNATURE_LEN = 3373
    VERIFYING_KEY_LEN = 1984
    NONCE_LEN = 32
    MIN_PASSPHRASE_LEN = 8

    WORD = Fiddle::SIZEOF_VOIDP
    # HideBuffer is { uint8_t *data; size_t len; size_t capacity; }.
    BUFFER_SIZE = WORD * 3
    # size_t and a pointer are the same width on every platform Ruby builds on.
    WORD_PACK = WORD == 8 ? "J" : "L"

    class LibraryNotFound < StandardError; end

    def self.library_names
      case RbConfig::CONFIG["host_os"]
      when /mswin|mingw|cygwin/ then ["hide_ffi.dll"]
      when /darwin/ then ["libhide_ffi.dylib"]
      else ["libhide_ffi.so"]
      end
    end

    # Mirrors the Python binding: an explicit override, then the copy shipped
    # beside the gem, then whatever the system loader can find.
    def self.load_library
      here = File.dirname(__FILE__)
      candidates = library_names.map { |name| File.join(here, name) }

      override = ENV["HIDE_LIBRARY"]
      candidates.unshift(override) if override && !override.empty?

      candidates.each do |candidate|
        return Fiddle.dlopen(candidate) if File.exist?(candidate)
      end

      begin
        Fiddle.dlopen(library_names.first)
      rescue Fiddle::DLError
        raise LibraryNotFound,
              "the HIDE native library was not found. Install a gem that " \
              "bundles it, or set HIDE_LIBRARY to the path of " \
              "#{library_names.first} built by `cargo build -p hide-ffi`."
      end
    end

    LIB = load_library

    VOIDP = Fiddle::TYPE_VOIDP
    INT32 = Fiddle::TYPE_INT
    SIZE_T = Fiddle::TYPE_SIZE_T
    VOID = Fiddle::TYPE_VOID
    UINT64 = Fiddle::TYPE_LONG_LONG

    SIGNATURES = {
      hide_error_message: [[INT32], VOIDP],
      hide_version: [[], VOIDP],
      # A 24-byte struct return is passed through a hidden out-pointer by both
      # the SysV and the Windows x64 ABI, so binding it this way is the
      # portable spelling; see empty_buffer for the fallback.
      hide_buffer_empty: [[VOIDP], VOID],
      hide_buffer_free: [[VOIDP], VOID],
      hide_keypair_generate: [[VOIDP, VOIDP], INT32],
      hide_inspect_key: [[VOIDP, SIZE_T, VOIDP], INT32],
      hide_secret_key_open: [[VOIDP, SIZE_T, VOIDP, VOIDP], INT32],
      hide_secret_key_protect: [[VOIDP, VOIDP, VOIDP], INT32],
      hide_secret_key_public: [[VOIDP, VOIDP], INT32],
      hide_secret_key_free: [[VOIDP], VOID],
      hide_public_key_armor: [[VOIDP, SIZE_T, VOIDP], INT32],
      hide_public_key_dearmor: [[VOIDP, VOIDP], INT32],
      hide_encrypt: [[VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, VOIDP, VOIDP], INT32],
      hide_decrypt: [[VOIDP, SIZE_T, VOIDP, VOIDP, VOIDP, VOIDP], INT32],
      hide_identity_generate: [[VOIDP, VOIDP], INT32],
      hide_signing_identity_open: [[VOIDP, SIZE_T, VOIDP, VOIDP], INT32],
      hide_signing_identity_public: [[VOIDP, VOIDP], INT32],
      hide_signing_identity_free: [[VOIDP], VOID],
      hide_sign_message: [[VOIDP, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP], INT32],
      hide_verify_message: [[VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T], INT32],
      hide_challenge_new: [[VOIDP, UINT64, UINT64, VOIDP], INT32],
      hide_challenge_answer: [[VOIDP, VOIDP, SIZE_T, VOIDP], INT32],
      hide_spent_nonces_new: [[], VOIDP],
      hide_spent_nonces_free: [[VOIDP], VOID],
      hide_challenge_accept: [[VOIDP, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T, UINT64], INT32]
    }.freeze

    FUNCTIONS = SIGNATURES.each_with_object({}) do |(name, (args, ret)), acc|
      acc[name] = Fiddle::Function.new(LIB[name.to_s], args, ret, name: name.to_s)
    end.freeze

    def self.call(name, *args)
      FUNCTIONS.fetch(name).call(*args)
    end

    # A static C string owned by the library; never freed by us.
    def self.static_string(pointer)
      return "" if pointer.null?

      Fiddle::Pointer.new(pointer.to_i).to_s.force_encoding(Encoding::UTF_8)
    end

    # Scratch space for one HideBuffer, zeroed the way hide_buffer_empty zeroes it.
    def self.empty_buffer
      slot = Fiddle::Pointer.malloc(BUFFER_SIZE, Fiddle::RUBY_FREE)
      slot[0, BUFFER_SIZE] = "\x00" * BUFFER_SIZE
      call(:hide_buffer_empty, slot)
      slot
    end

    def self.read_word(slot, index)
      slot[index * WORD, WORD].unpack1(WORD_PACK)
    end

    # Copies a native buffer out and frees the original. The length field is
    # the only thing consulted: text from this library is length-prefixed, not
    # NUL-terminated, because metadata is attacker-controlled and a NUL in it
    # would silently truncate a C-string read.
    def self.take(slot)
      data = read_word(slot, 0)
      len = read_word(slot, 1)
      bytes =
        if data.zero? || len.zero?
          +""
        else
          Fiddle::Pointer.new(data, len)[0, len]
        end
      bytes.force_encoding(Encoding::BINARY)
    ensure
      call(:hide_buffer_free, slot)
    end

    # Metadata arrives as length-prefixed UTF-8; empty means absent.
    def self.take_text(slot)
      raw = take(slot)
      return nil if raw.empty?

      raw.dup.force_encoding(Encoding::UTF_8).scrub
    end

    # A slot holding one pointer-sized out-parameter.
    def self.pointer_slot
      slot = Fiddle::Pointer.malloc(WORD, Fiddle::RUBY_FREE)
      slot[0, WORD] = "\x00" * WORD
      slot
    end
  end
end
