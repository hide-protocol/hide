# frozen_string_literal: true

require "fiddle"
require "rbconfig"

module Hide
  # Raw access to the HIDE C core.
  #
  # fiddle rather than the ffi gem: fiddle ships with Ruby (a default gem up
  # to 3.4, a bundled gem from 4.0), so installing this gem needs no compiler,
  # and the ABI is described in exactly one place.
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

    # The native library and this binding are not the same release.
    class VersionMismatch < StandardError; end

    def self.library_names
      case RbConfig::CONFIG["host_os"]
      when /mswin|mingw|cygwin/ then ["hide_ffi.dll"]
      when /darwin/ then ["libhide_ffi.dylib"]
      else ["libhide_ffi.so"]
      end
    end

    # Mirrors the Python binding: an explicit override, else the copy shipped
    # beside this file, and nothing else.
    #
    # Only absolute paths are ever handed to the loader. A bare file name would
    # let it search the current directory, PATH or LD_LIBRARY_PATH, which
    # replaces the cryptographic core with no opt-in at all.
    def self.locate_library
      override = ENV["HIDE_LIBRARY"]
      # HIDE_LIBRARY replaces the whole cryptographic core, so one settable env
      # var must not be enough: it is honoured only with an explicit second opt-in.
      # Once opted in it is the answer, not one candidate among several: failing
      # to load it is an error rather than a reason to quietly use another copy.
      allowed = ENV["HIDE_ALLOW_LIBRARY_OVERRIDE"] == "1"
      return File.expand_path(override) if allowed && override && !override.empty?

      here = File.expand_path(__dir__)
      packaged = library_names.map { |name| File.join(here, name) }.find { |path| File.file?(path) }
      return packaged if packaged

      raise LibraryNotFound,
            "the HIDE native library (#{library_names.first}) was not found for " \
            "#{RUBY_PLATFORM}. Install the hide-protocol platform gem for this " \
            "machine, which bundles it. Developers: set HIDE_LIBRARY to the path of " \
            "#{library_names.first} built by `cargo build -p hide-ffi` " \
            "AND HIDE_ALLOW_LIBRARY_OVERRIDE=1."
    end

    def self.load_library(path)
      Fiddle.dlopen(path)
    rescue Fiddle::DLError => e
      raise LibraryNotFound, "the HIDE native library at #{path} could not be loaded: #{e.message}"
    end

    # The version of this binding, from the gemspec it is built from: the one
    # place a release writes it, shipped inside the gem for this purpose. The
    # file beside lib answers first, because an older installed copy of the
    # gem must not speak for this code.
    def self.binding_version
      gemspec = File.expand_path("../../hide-protocol.gemspec", __dir__)
      declared = File.file?(gemspec) && File.read(gemspec, encoding: "UTF-8")[/spec\.version = "([^"]+)"/, 1]
      return declared if declared

      activated = defined?(Gem) && Gem.loaded_specs["hide-protocol"]
      return activated.version.to_s if activated

      raise VersionMismatch,
            "cannot tell which version of hide-protocol this is, so the native " \
            "library cannot be checked against it. Install the gem rather than " \
            "copying its lib directory."
    end

    def self.version_triple(text, what)
      match = /\A(\d+)\.(\d+)\.(\d+)/.match(text.to_s)
      raise VersionMismatch, "the #{what} version #{text.inspect} is not major.minor.patch" unless match

      match.captures.map(&:to_i)
    end

    # Refuses a core whose major.minor.patch differs from this binding's.
    #
    # Exact, not merely compatible: the core enforces checks this binding only
    # documents (reserved contexts, metadata rules, limits), so a stale core
    # beside a newer binding would silently lose them. Pre-release and build
    # suffixes are not compared.
    def self.check_version(core, binding = BINDING_VERSION)
      return if version_triple(core, "core") == version_triple(binding, "binding")

      raise VersionMismatch,
            "the HIDE native library is version #{core} but this binding is " \
            "#{binding}; install matching versions of both"
    end

    BINDING_VERSION = binding_version
    # The absolute path the core was loaded from.
    LIBRARY_PATH = locate_library.freeze
    LIB = load_library(LIBRARY_PATH)

    VOIDP = Fiddle::TYPE_VOIDP
    INT32 = Fiddle::TYPE_INT
    SIZE_T = Fiddle::TYPE_SIZE_T
    VOID = Fiddle::TYPE_VOID
    UINT64 = Fiddle::TYPE_LONG_LONG

    SIGNATURES = {
      hide_error_message: [[INT32], VOIDP],
      hide_version: [[], VOIDP],
      # hide_buffer_empty is deliberately not bound. It returns a 24-byte
      # struct by value, which fiddle cannot describe; spelling it as a
      # function taking a hidden out-pointer matches the x86-64 ABIs only
      # (AAPCS64 passes that address in x8, not as the first argument).
      # empty_buffer zero-fills the slot instead, which is all it does.
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
      hide_challenge_accept: [[VOIDP, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T, UINT64], INT32],
      hide_identity_verify: [[VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP], INT32],
      hide_identity_trusts_device: [[VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP], INT32],
      hide_identity_head: [[VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP], INT32],
      hide_epoch_verify: [[VOIDP, SIZE_T, VOIDP], INT32],
      hide_epoch_public_key: [[VOIDP, SIZE_T, UINT64, VOIDP], INT32],
      hide_transparency_verify_inclusion: [
        [VOIDP, SIZE_T, UINT64, UINT64, VOIDP, SIZE_T, VOIDP, SIZE_T], INT32
      ],
      hide_transparency_verify_consistency: [
        [UINT64, UINT64, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T], INT32
      ],
      hide_identity_verify_pinned: [
        [VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP], INT32
      ],
      hide_epoch_verify_bound: [
        [VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP, SIZE_T, VOIDP], INT32
      ],
      hide_checkpoint_verify: [
        [VOIDP, SIZE_T, VOIDP, VOIDP, SIZE_T, VOIDP, VOIDP], INT32
      ]
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

    check_version(static_string(call(:hide_version)))

    # Scratch space for one HideBuffer, zeroed: exactly what hide_buffer_empty
    # returns, without a struct-by-value call fiddle cannot make portably.
    def self.empty_buffer
      slot = Fiddle::Pointer.malloc(BUFFER_SIZE, Fiddle::RUBY_FREE)
      slot[0, BUFFER_SIZE] = "\x00" * BUFFER_SIZE
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

    # Reads a size_t out-parameter written into a pointer-sized slot.
    def self.read_count(slot)
      read_word(slot, 0)
    end

    # A slot holding one pointer-sized out-parameter.
    def self.pointer_slot
      slot = Fiddle::Pointer.malloc(WORD, Fiddle::RUBY_FREE)
      slot[0, WORD] = "\x00" * WORD
      slot
    end

    # A slot for a uint64_t out-parameter. Always 8 bytes, unlike a size_t
    # slot, so it is read with "Q" rather than WORD_PACK.
    def self.uint64_slot
      slot = Fiddle::Pointer.malloc(8, Fiddle::RUBY_FREE)
      slot[0, 8] = "\x00" * 8
      slot
    end

    def self.read_uint64(slot)
      slot[0, 8].unpack1("Q")
    end
  end
end
