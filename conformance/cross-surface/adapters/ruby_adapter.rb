# frozen_string_literal: true

# Drives the Ruby SDK for the cross-surface interop matrix. Two commands:
#   ruby ruby_adapter.rb encrypt <public-key> <plaintext> <out-container>
#   ruby ruby_adapter.rb decrypt <secret-key> <container> <out-plaintext>

require "hide_protocol"

def read_binary(path)
  File.binread(path)
end

def write_binary(path, data)
  File.binwrite(path, data)
end

command, key_path, input_path, output_path = ARGV
abort "usage: #{$PROGRAM_NAME} encrypt|decrypt <key> <input> <output>" if output_path.nil?

case command
when "encrypt"
  container = Hide.encrypt(
    read_binary(input_path),
    recipients: [read_binary(key_path)],
    filename: "ruby.txt"
  )
  write_binary(output_path, container)
when "decrypt"
  secret = Hide::SecretKey.open(read_binary(key_path))
  begin
    write_binary(output_path, Hide.decrypt(read_binary(input_path), secret).plaintext)
  ensure
    secret.close
  end
else
  abort "unknown command: #{command}"
end
