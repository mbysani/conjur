# AuthenticationService represents the authenticator itself, which 
# has a Conjur id that:
#
# * Identifies a policy.
# * Identifies a webservice.
# * Is a naming prefix to CA cert and key variables.
# * Is a naming prefix to the application hosts.
module Authentication
  module AuthnK8s
    class AuthenticationService
      attr_reader :id

      # Constructs AuthenticationService from the +id+, which is typically something like
      # conjur/authn-k8s/<cluster-name>.
      def initialize id
        @id = id
      end

      # Generates a CA certificate and key and store them in Conjur variables.  
      def initialize_ca
        cert, key = CA.generate(cert_subject)
        save_in_conjur(cert, key)
      end

      # TODO: this dep should be injected
      def conjur_account
        Conjur.configuration.account
      end

      def ca_cert_variable
        Resource["#{service_id}/ca/cert"]
      end

      def ca_key_variable
        Resource["#{service_id}/ca/key"]
      end

      # Initialize CA from Conjur variables
      def load_ca
        ca_cert = OpenSSL::X509::Certificate.new(ca_cert_variable.last_secret)
        ca_key = OpenSSL::PKey::RSA.new(ca_key_variable.last_secret)
        CA.new(ca_cert, ca_key)
      end

      private

      def cert_subject
        "/CN=#{common_name}/OU=Conjur Kubernetes CA/O=#{conjur_account}"
      end

      def common_name
        id.gsub('/', '.')
      end

      # TODO: extract into reusable object
      def service_id 
        "#{conjur_account}:variable:#{id}"
      end
      
      # Stores the CA cert and key in variables.
      def save_in_conjur(cert, key)
        Secret.create(resource_id: ca_cert_variable.id, value: cert.to_pem)
        Secret.create(resource_id: ca_key_variable.id, value: key.to_pem)
      end
    end
  end
end
