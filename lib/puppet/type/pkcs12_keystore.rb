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

    attr_reader :openssl_object

    munge do |value|
      is_absolute_path = Puppet::FileSystem.pathname(value).absolute?
      if is_absolute_path
        Puppet.debug("Munging cert `#{value}` as a file.")
        raise Puppet::Error, "Provided certificate file `#{value}` does not exist." unless Puppet::FileSystem.exist?(value)
        raise Puppet::Error, "Provided certificate path `#{value}` is not a file." unless Puppet::FileSystem.file?(value)

        cert_data = Puppet::FileSystem.read(value)
      else
        cert_data = value
      end

      Puppet.debug("Trying to parse cert data: `#{cert_data}`")
      begin
        @openssl_object = OpenSSL::X509::Certificate.new(cert_data)
        resource.munge_openssl(@openssl_object)
      rescue OpenSSL::X509::CertificateError => e
        raise Puppet::Error, "Provided certificate file does not contain a valid cert: #{e.message}" if is_absolute_path

        raise Puppet::Error, "Provided certificate is not a valid cert: #{e.message}"
      end
    end
  end

  newproperty(:ca_certificates, array_matching: :all) do
    desc 'List of (intermediate) CA certificate contents or paths that should be present in the keystore.'

    attr_reader :openssl_objects

    munge do |value|
      is_absolute_path = Puppet::FileSystem.pathname(value).absolute?
      if is_absolute_path
        Puppet.debug("Munging CA cert `#{value}` as a file.")
        raise Puppet::Error, "Provided CA certificate file `#{value}` does not exist." unless Puppet::FileSystem.exist?(value)
        raise Puppet::Error, "Provided CA certificate path `#{value}` is not a file." unless Puppet::FileSystem.file?(value)

        cert_data = Puppet::FileSystem.read(value)
      else
        cert_data = value
      end

      Puppet.debug("Trying to parse CA cert data: `#{cert_data}`")
      begin
        object = OpenSSL::X509::Certificate.new(cert_data)
        (@openssl_objects ||= []).append(object)
        resource.munge_openssl(object)
      rescue OpenSSL::X509::CertificateError => e
        raise Puppet::Error, "Provided CA certificate file does not contain a valid cert: #{e.message}" if is_absolute_path

        raise Puppet::Error, "Provided CA certificate is not a valid cert: #{e.message}"
      end
    end

    def insync?(is)
      is.to_a.sort == should.to_a.sort
    end
  end

  newproperty(:private_key) do
    desc 'Private key content or path that should be present in the keystore. Requires a matching `certificate`.'

    attr_reader :openssl_object

    def path?
      Puppet::FileSystem.pathname(shouldorig[0]).absolute?
    end

    munge do |value|
      is_absolute_path = Puppet::FileSystem.pathname(value).absolute?
      if is_absolute_path
        Puppet.debug("Munging private key `#{value}` as a file.")
        raise Puppet::Error, "Provided private key file `#{value}` does not exist." unless Puppet::FileSystem.exist?(value)
        raise Puppet::Error, "Provided private key path `#{value}` is not a file." unless Puppet::FileSystem.file?(value)

        pk_data = Puppet::FileSystem.read(value)
      else
        pk_data = value
      end

      Puppet.debug('Trying to parse private key data')
      begin
        @openssl_object = OpenSSL::PKey.read(pk_data, resource&.original_parameters&.[](:private_key_password))
        resource.munge_openssl(@openssl_object)
      rescue OpenSSL::PKey::PKeyError => e
        raise Puppet::Error, "Provided private key file does not contain a valid key: #{e.message}" if is_absolute_path

        raise Puppet::Error, "Provided private key is not a valid key: #{e.message}"
      end
    end
  end

  newparam(:password) do
    desc 'The keystore password.'
    sensitive(true)
    isrequired
  end

  newproperty(:friendly_name) do
    desc 'Description of the keystore (Openssl `friendlyName` attribute).'
  end

  newparam(:private_key_password) do
    desc 'Optional. Password the source private key is encrypted with.'
    sensitive(true)
  end

  newparam(:force, parent: Puppet::Parameter::Boolean) do
    desc 'Whether to replace the keystore if unlocking fails for some reason.'

    defaultto false
  end

  autorequire(:file) do
    %i[certificate private_key ca_certificates].map do |prop|
      [property(prop).shouldorig].flatten.select { |f| Puppet::FileSystem.pathname(f).absolute? } if self[prop]
    end.flatten
  end

  validate do
    raise Puppet::Error, 'Cannot store a private key without a certificate!' if self[:private_key] && !self[:certificate]
    raise Puppet::Error, 'Cannot store a certificate without a private key! Did you mean to create a trust store with only ca_certificates?' if self[:certificate] && !self[:private_key]
    raise Puppet::Error, 'Provided certificate does not match provided private key!' if self[:certificate] && self[:private_key] && !@parameters[:certificate].openssl_object.check_private_key(@parameters[:private_key].openssl_object)
  end

  def generate
    [Puppet::Type.type(:file).new(
      ensure: self[:ensure] == :absent ? :absent : 'file',
      title: self[:path],
      owner: self[:owner],
      group: self[:group],
      mode: self[:mode]
    )]
  end

  def self.instances
    []
  end

  def retrieve
    data = {
      ensure: property(:ensure).retrieve,
    }

    return data if data[:ensure] == :absent || self[:ensure] == :absent # Do not try to read data if we don't need it

    begin
      Puppet.debug("Attempting to retrieve keystore `#{self[:path]}`")
      keystore = OpenSSL::PKCS12.new(Puppet::FileSystem.read(self[:path]), self[:password])
      data.merge!({ certificate: munge_openssl(keystore.certificate) }) if keystore.certificate
      data.merge!({ ca_certificates: keystore.ca_certs.map { |ca| munge_openssl(ca) } }) if keystore.ca_certs
      data.merge!({ private_key: munge_openssl(keystore.key) }) if keystore.key
    rescue OpenSSL::PKCS12::PKCS12Error => e
      raise Puppet::Error, "Failed to read keystore `#{self[:path]}`. Invalid file or wrong password? (#{e.message})" unless self[:force]

      # If we fail to open the keystore and force is enabled, act as if the keystore is not there.
      warning("Failed to read keystore `#{self[:path]}`, but force was set to true. Recreating keystore.")
      return { ensure: :absent }
    end

    data.merge!({ friendly_name: provider.friendly_name })

    data
  end

  def munge_openssl(value)
    '{sha256}' + OpenSSL::Digest::SHA256.hexdigest(value.to_der)
  end
end
