# frozen_string_literal: true

require 'openssl'
require 'puppet/file_system'

Puppet::Type.type(:pkcs12_keystore).provide(:openssl) do
  desc 'Manage a pkcs12 keystore with OpenSSL Ruby bindings.'

  commands openssl: 'openssl'

  def exists?
    Puppet::FileSystem.exist?(resource[:path])
  end

  def certificate
    keystore.certificate
  end

  def ca_certificates
    keystore.ca_certs
  end

  def private_key
    keystore.key
  end

  def create
    raise ArgumentError, 'Cannot create a keystore without any (CA) certificates!' unless resource[:certificate] || resource[:ca_certificates]

    Puppet::FileSystem.replace_file(resource[:path]) do |file|
      if resource[:private_key]
        file.write(OpenSSL::PKCS12.create(resource[:password], resource[:friendly_name], resource[:private_key], resource[:certificate], resource[:ca_certificates]))
      else
        # At the time of writing, Ruby's openssl bindings do not allow creating a pkcs12 store with only CA's.
        # Use the openssl cli to do this instead.
        cert_tempfile = Puppet::FileSystem::Uniquefile.new(Puppet::FileSystem.basename_string(resource[:path]), Puppet::FileSystem.dir_string(resource[:path]), mode: File::APPEND)
        begin
          cert_tempfile.write(resource[:certificate].to_pem) if resource[:certificate]
          resource[:ca_certificates].each { |ca| cert_tempfile.write(ca.to_pem) } if resource[:ca_certificates]
          cert_tempfile.flush

          exec = [
            command('openssl'),
            'pkcs12',
            '-export',
            '-nokeys',
            '-in', cert_tempfile.path,
            '-out', file.path,
            '-passout', 'env:KEYSTORE_PASSWORD',
          ]
          env = { 'KEYSTORE_PASSWORD' => resource[:password].to_s } # Force empty password if nil

          execute(exec, { failonfail: true, combine: true, custom_environment: env })
        ensure
          cert_tempfile.close!
        end
      end
    end
  end

  def destroy
    Puppet::FileSystem.unlink(resource[:path])
  end

  def keystore
    unless @keystore
      begin
        @keystore = OpenSSL::PKCS12.new(Puppet::FileSystem.read(resource[:path]), resource[:password])
      rescue OpenSSL::PKCS12::PKCS12Error => p12_error
        raise ArgumentError, "Failed to open keystore. Invalid file or wrong password? (#{p12_error.message})"
      rescue => e
        raise Puppet::Error, "Failed to open keystore: #{e.message}"
      end
    end
    @keystore
  end

  def munge_cert(value)
    is_path = Puppet::FileSystem.pathname(value).absolute?
    if is_path
      Puppet.debug("Munging cert `#{value}` as a file.")
      raise ArgumentError, "Provided certificate file `#{value}` does not exist." unless Puppet::FileSystem.exist?(value)
      raise ArgumentError, "Provided certificate path `#{value}` is not a file." unless Puppet::FileSystem.file?(value)
      cert_data = Puppet::FileSystem.read(value)
    else
      cert_data = value
    end

    Puppet.debug("Trying to parse cert data: `#{cert_data}`")
    begin
      OpenSSL::X509::Certificate.new(cert_data)
    rescue => e
      raise ArgumentError, "Provided certificate file does not contain a valid cert: #{e.message}" if is_path

      raise ArgumentError, "Provided certificate is not a valid cert: #{e.message}"
    end
  end

  def munge_pkey(value)
    is_path = Puppet::FileSystem.pathname(value).absolute?
    if is_path
      Puppet.debug("Munging private key `#{value}` as a file.")
      raise ArgumentError, "Provided private key file `#{value}` does not exist." unless Puppet::FileSystem.exist?(value)
      raise ArgumentError, "Provided private key path `#{value}` is not a file." unless Puppet::FileSystem.file?(value)
      pk_data = Puppet::FileSystem.read(value)
    else
      pk_data = value
    end

    Puppet.debug("Trying to parse private key data: `#{cert_data}`")
    begin
      OpenSSL::PKey.read(pk_data)
    rescue => e
      raise ArgumentError, "Provided private key file does not contain a valid key: #{e.message}" if is_path

      raise ArgumentError, "Provided private key is not a valid key: #{e.message}"
    end
  end
end
