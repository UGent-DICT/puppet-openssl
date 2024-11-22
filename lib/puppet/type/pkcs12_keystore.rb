# frozen_string_literal: true

require 'puppet/parameter/boolean'
require 'puppet/file_system'
require 'openssl'

Puppet::Type.newtype(:pkcs12_keystore) do
  desc 'A PKCS12 keystore'

  ensurable

  newparam(:path, namevar: true) do
    desc 'Path to the PKCS12 keystore.'

    validate do |value|
      raise Puppet::Error, "Path must be absolute: #{path}" unless Puppet::FileSystem.pathname(value).absolute?
    end
  end

  newparam(:owner) do
    desc 'Owner of the keystore on the filesystem.'
    defaultto 'root'
  end

  newparam(:group) do
    desc 'Group of the keystore on the filesystem.'
    defaultto 'root'
  end

  newparam(:mode) do
    desc 'Mode of the keystore on the filesystem.'
    defaultto '0640'
  end

  newproperty(:certificate) do
    desc 'Certificate content or path that should be present in the keystore. Without a corresponding private key, this cert is an implicit ca-certificate.'

    munge do |value|
      is_path = Puppet::FileSystem.pathname(value).absolute?
      if is_path
        Puppet.debug("Munging cert `#{value}` as a file.")
        raise Puppet::Error, "Provided certificate file `#{value}` does not exist." unless Puppet::FileSystem.exist?(value)
        raise Puppet::Error, "Provided certificate path `#{value}` is not a file." unless Puppet::FileSystem.file?(value)

        cert_data = Puppet::FileSystem.read(value)
      else
        cert_data = value
      end

      Puppet.debug("Trying to parse cert data: `#{cert_data}`")
      begin
        OpenSSL::X509::Certificate.new(cert_data)
      rescue OpenSSL::X509::CertificateError => e
        raise Puppet::Error, "Provided certificate file does not contain a valid cert: #{e.message}" if is_path

        raise Puppet::Error, "Provided certificate is not a valid cert: #{e.message}"
      end
    end

    def is_to_s(value)
      super(value.is_a?(OpenSSL::X509::Certificate) ? OpenSSL::Digest::SHA256.new(value.to_der).to_s : value)
    end

    def should_to_s(value)
      super(value.is_a?(OpenSSL::X509::Certificate) ? OpenSSL::Digest::SHA256.new(value.to_der).to_s : value)
    end
  end

  newproperty(:ca_certificates, array_matching: :all) do
    desc 'List of (intermediate) CA certificate contents or paths that should be present in the keystore.'

    munge do |value|
      provider.munge_cert(value) if provider.respond_to?(:munge_cert)
    end

    def insync?(is)
      is.sort_by(&:serial) == should.sort_by(&:serial)
    end

    def is_to_s(value)
      super(value.map do |cert|
        cert.is_a?(OpenSSL::X509::Certificate) ? OpenSSL::Digest::SHA256.new(cert.to_der).to_s : cert
      end)
    end

    def should_to_s(value)
      super(value.map do |cert|
        cert.is_a?(OpenSSL::X509::Certificate) ? OpenSSL::Digest::SHA256.new(cert.to_der).to_s : cert
      end)
    end
  end

  newproperty(:private_key) do
    desc 'Private key content or path that should be present in the keystore. Requires a matching `certificate`.'
    sensitive

    munge do |value|
      is_path = Puppet::FileSystem.pathname(value).absolute?
      if is_path
        Puppet.debug("Munging private key `#{value}` as a file.")
        raise Puppet::Error, "Provided private key file `#{value}` does not exist." unless Puppet::FileSystem.exist?(value)
        raise Puppet::Error, "Provided private key path `#{value}` is not a file." unless Puppet::FileSystem.file?(value)

        pk_data = Puppet::FileSystem.read(value)
      else
        pk_data = value
      end

      Puppet.debug("Trying to parse private key data: `#{pk_data}`")
      begin
        OpenSSL::PKey.read(pk_data, self[:private_key_password])
      rescue OpenSSL::PKey::PKeyError => e
        raise Puppet::Error, "Provided private key file does not contain a valid key: #{e.message}" if is_path

        raise Puppet::Error, "Provided private key is not a valid key: #{e.message}"
      end
    end

    def is_to_s(value)
      super(value.is_a?(OpenSSL::PKey::PKey) ? OpenSSL::Digest::SHA256.new(value.to_der).to_s : value)
    end

    def should_to_s(value)
      super(value.is_a?(OpenSSL::PKey::PKey) ? OpenSSL::Digest::SHA256.new(value.to_der).to_s : value)
    end
  end

  newparam(:password) do
    desc 'The keystore password.'
    sensitive
    isrequired
  end

  newproperty(:friendly_name) do
    desc 'Description of the keystore (Openssl `friendlyName` attribute).'
  end

  newparam(:private_key_password) do
    desc 'Optional. Password the source private key is encrypted with.'
    sensitive
  end

  newparam(:force, parent: Puppet::Parameter::Boolean) do
    desc 'Whether to replace the keystore if unlocking fails for some reason.'

    defaultto true
  end

  autorequire(:file) do
    %i[certificate private_key ca_certificates].map do |prop|
      [property(prop).shouldorig].flatten.select { |f| Puppet::FileSystem.pathname(f).absolute? } if self[prop]
    end.flatten
  end

  validate do
    raise Puppet::Error, 'Cannot store a private key without a certificate!' if self[:private_key] && !self[:certificate]
    raise Puppet::Error, 'Provided certificate does not match provided private key!' if self[:certificate] && self[:private_key] && !self[:certificate].check_private_key(self[:private_key])
  end

  def generate
    if self[:ensure] == :absent
      []
    else
      [Puppet::Type.type(:file).new(
        ensure: 'file',
        title: self[:path],
        owner: self[:owner],
        group: self[:group],
        mode: self[:mode]
      )]
    end
  end

  def self.instances
    [] # Make `puppet resource` work
  end
end
