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
      raise ArgumentError, "Path must be absolute: #{path}" unless Puppet::FileSystem.pathname(value).absolute?
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
      provider.munge_cert(value) if provider.respond_to?(:munge_cert)
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

    munge do |value|
      provider.munge_pkey(value) if provider.respond_to?(:munge_pkey)
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
    isrequired
  end

  newparam(:friendly_name) do
    desc 'Description of the keystore (Openssl `friendlyName` attribute).'
  end

  newparam(:private_key_password) do
    desc 'Optional. Password the source private key is encrypted with.'
  end

  newparam(:force, parent: Puppet::Parameter::Boolean) do
    desc 'Whether to replace the keystore if unlocking with `password` fails.'

    defaultto true
  end

  autorequire(:file) do
    [:certificate, :private_key, :ca_certificates].map { |prop|
      [property(prop).shouldorig].flatten.select { |f| Puppet::FileSystem.pathname(f).absolute? } if self[prop]
    }.flatten
  end

  validate do
    raise ArgumentError, 'Cannot store a private key without a certificate!' if self[:private_key] && !self[:certificate]
    raise Puppet::Error, 'Provided certificate does not match provided private key!' if self[:certificate] && self[:private_key] && !self[:certificate].check_private_key(self[:private_key])
  end

  def generate
    if self[:ensure] != :absent
      [Puppet::Type.type(:file).new(
        ensure: 'file',
        title: self[:path],
        owner: self[:owner],
        group: self[:group],
        mode: self[:mode],
      )]
    else
      []
    end
  end

  def self.instances
    [] # Make `puppet resource` work
  end
end
