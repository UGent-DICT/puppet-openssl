# frozen_string_literal: true

require 'openssl'
require 'puppet/file_system'

Puppet::Type.type(:pkcs12_keystore).provide(:openssl) do
  desc 'Manage a pkcs12 keystore with OpenSSL Ruby bindings.'

  commands openssl: 'openssl'

  def exists?
    Puppet::FileSystem.exist?(resource[:path])
  end

  mk_resource_methods

  def friendly_name
    exec = [
      command('openssl'),
      'pkcs12',
      '-nokeys',
      '-info',
      '-in', resource[:path],
      '-passin', 'env:KEYSTORE_PASSWORD',
    ]
    env = { 'KEYSTORE_PASSWORD' => resource[:password].to_s } # Force empty password if nil

    execute(exec, { failonfail: true, combine: true, custom_environment: env })[%r{friendlyName:\s+\K.+$}]
  end

  def initialize(resource = nil)
    super(resource)

    return unless exists?

    begin
      keystore = OpenSSL::PKCS12.new(Puppet::FileSystem.read(resource[:path]), resource[:password])
    rescue OpenSSL::PKCS12::PKCS12Error => e
      raise Puppet::Error, "Failed to read keystore #{resource[:path]}. Invalid file or wrong password? (#{e.message})" unless resource[:force]
    end
    @property_hash = {
      certificate: keystore.certificate,
      ca_certificates: keystore.ca_certs,
      private_key: keystore.key,
    }
  end

  def flush
    # We cannot update individual attributes, so just recreate the keystore.
    create
  end

  def create
    raise Puppet::Error, 'Cannot create a keystore without any (CA) certificates!' unless resource[:certificate] || resource[:ca_certificates]

    Puppet::FileSystem.replace_file(resource[:path]) do |file|
      if resource[:private_key]
        file.write(OpenSSL::PKCS12.create(resource[:password], resource[:friendly_name], resource[:private_key], resource[:certificate], resource[:ca_certificates]))
      else
        # At the time of writing, Ruby's openssl bindings do not allow creating a pkcs12 store with only CA's.
        # Use the openssl cli to do this instead.
        cert_tempfile = Puppet::FileSystem::Uniquefile.new(Puppet::FileSystem.basename_string(resource[:path]), Puppet::FileSystem.dir_string(resource[:path]), mode: File::APPEND)
        begin
          cert_tempfile.write(resource[:certificate].to_pem) if resource[:certificate]
          resource[:ca_certificates]&.each { |ca| cert_tempfile.write(ca.to_pem) }
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
end
