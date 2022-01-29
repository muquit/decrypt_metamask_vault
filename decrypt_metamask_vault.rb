#!/usr/bin/env ruby
########################################################################
# Decrypt Metamask Vault with supplied password. 
# It's broken: ruby does not seem to like 16 byte iv for AES-256 GCM
# muquit@muquit.com Nov-20-2021 
########################################################################

require 'io/console'
require 'json'
require 'base64'
require 'openssl'
require 'encryptor'

require 'pp'

class MetamaskVaultDecryptor
  def initialize
    $stdout.sync = true
    $stderr.sync = true
    @me = File.basename($0)
  end

  def log(msg)
    t = Time.new()
    puts "#{t}: #{msg}"
  end

  def log_fatal(msg)
    t = Time.new()
    puts "FATAL ERROR: #{msg}"
    exit 1
  end

  def check_args
    if ARGV.length != 1 
      puts "Usage: #{@me} <vault.json>"
      exit 1
    end
    file = ARGV[0]
    if !File.exist?(file)
      log_fatal("File #{file} does not exist")
    end
  end

  #==================================================================== 
  # It uses PBKDF2 with AES-GCM 256, SHA-256 with 10000 iteration
  # iv length is 16 bytes
  #==================================================================== 
  def key_from_password(password, salt_base64)
    log "'#{password}'"
    salt = Base64.decode64(salt_base64)
    digest = OpenSSL::Digest::SHA256.new()
    digest_len = digest.digest_length
    log "Digest length: #{digest_len}"
    key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 10000, digest_len, digest)
    log "Key len: #{key.length}"
    keyb64 = Base64.encode64(key)
    return key
  end

  def decrypt_with_key(key, json_obj)
    cipher_text_base64 = json_obj['data']
    log "Data: #{cipher_text_base64}"
    cipher_text = Base64.decode64(cipher_text_base64)
    iv_base64 = json_obj['iv']
    log "iv: #{iv_base64}"
    iv = Base64.decode64(iv_base64)
    decipher = OpenSSL::Cipher.new('aes-256-gcm')
    decipher.decrypt
    decipher.key = key
    log "iv len: #{iv.length}"
    decipher.iv_len = iv.length
    decipher.iv = iv
    plain = decipher.update(cipher_text) + decipher.final
    pp plain
  end

  def decrypt(password, vault_json_file)
    json_str = File.read(vault_json_file)
    json = JSON.parse(json_str)
    salt_base64 = json["salt"]
    log ">> Salt: #{salt_base64}"
    key = key_from_password(password, salt_base64)
    decrypt_with_key(key, json)
  end

  def doit
    check_args()
    password = IO::console.getpass "Enter Metamask Password: "
    decrypt(password, ARGV[0])
  end

end

if __FILE__ == $0
  MetamaskVaultDecryptor.new.doit()
end

