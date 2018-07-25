require 'kubeclient'

module Authentication
  module AuthnK8s
    module KubeClientFactory

      MissingServiceAccountDirectory = ::Util::ErrorClass.new(
        "Kubernetes serviceaccount dir '{0}' does not exist"
      )
      MissingEnvironmentVariable = ::Util::ErrorClass.new(
        "Expected environment variable '{0}' is not set"
      )
      
      KUBERNETES_SERVICEACCOUNT_DIR = '/var/run/secrets/kubernetes.io/serviceaccount'
      EXPECTED_ENV_VARS = %w[KUBERNETES_SERVICE_HOST KUBERNETES_SERVICE_PORT]

      def self.client(api: 'api', version: 'v1')
        validate_environment!
        Kubeclient::Client.new(full_url, version, options)
      end

      private

      def self.validate_environment! 
        validate_serviceaccount_dir_exists!
        validate_required_env_variables!
      end

      def self.validate_serviceaccount_dir_exists!
        return if File.exists?(KUBERNETES_SERVICEACCOUNT_DIR)
        raise MissingServiceAccountDirectory, KUBERNETES_SERVICEACCOUNT_DIR
      end

      def self.validate_required_env_variables!
        EXPECTED_ENV_VARS.each do |var|
          raise MissingEnvironmentVariable(var) unless ENV[var]
        end
      end

      def self.full_url
        "#{host_url}/#{api}"
      end

      def self.host_url
        "https://#{ENV['KUBERNETES_SERVICE_HOST']}:#{ENV['KUBERNETES_SERVICE_PORT']}"
      end

      def self.options
        {
          auth_options: {
            bearer_token_file: File.join(KUBERNETES_SERVICEACCOUNT_DIR, 'token')
          },
          ssl_options: {
            ca_file: File.join(KUBERNETES_SERVICEACCOUNT_DIR, 'ca.crt'),
            verify_ssl: OpenSSL::SSL::VERIFY_PEER
          }
        }
      end

    end
  end
end
