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

    execute(exec, { failonfail: true, combine: true, custom_environment: env })[%r{friendlyName:\s+\K.+$}] # Use regex slicing on the shell return string
  end

  def flush
    # We cannot update individual attributes, so just recreate the keystore.
    create unless resource.deleting?
  end

  def create
    raise Puppet::Error, 'Cannot create a keystore without any (CA) certificates!' unless resource[:certificate] || resource[:ca_certificates]

    Puppet::FileSystem.replace_file(resource[:path]) do |file|
      # Not using OpenSSL::PKCS12.create here because system openssl and puppet openssl can differ..
      in_tempfile = Puppet::FileSystem::Uniquefile.new(Puppet::FileSystem.basename_string(resource[:path]), Puppet::FileSystem.dir_string(resource[:path]), mode: File::APPEND)

      begin
        exec = [
          command('openssl'),
          'pkcs12',
          '-export',
          '-in', in_tempfile.path,
          '-out', file.path,
          '-passout', 'env:KEYSTORE_PASSWORD',
        ]
        env = { 'KEYSTORE_PASSWORD' => resource[:password].to_s } # Force empty password if nil

        exec.push('-name', resource[:friendly_name]) if resource[:friendly_name]

        if resource.parameters[:private_key]&.path?
          exec.push('-inkey', resource.original_parameters[:private_key])
        elsif resource[:private_key]
          # Write the original in case it's encrypted; less chances of leaking through the filesystem.
          in_tempfile.write(resource.original_parameters[:private_key])
          # In case the original_parameter lost its trailing newline. Openssl doesn't mind extra whitespace
          in_tempfile.write("\n")
        else
          exec.push('-nokeys')
        end

        if resource[:private_key_password]
          exec.push('-passin', 'env:PRIVATE_KEY_PASS')
          env.merge!({ 'PRIVATE_KEY_PASS' => resource[:private_key_password] })
        end

        in_tempfile.write(resource.parameters[:certificate].openssl_object.to_pem) if resource[:certificate]
        resource.parameters[:ca_certificates]&.openssl_objects&.each { |ca| in_tempfile.write(ca.to_pem) }

        in_tempfile.flush

        execute(exec, { failonfail: true, combine: true, custom_environment: env })
      ensure
        in_tempfile.close!
      end
    end
  end

  def destroy
    Puppet::FileSystem.unlink(resource[:path])
  end
end
