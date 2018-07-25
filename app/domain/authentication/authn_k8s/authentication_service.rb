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
        subject = "/CN=#{id.gsub('/', '.')}/OU=Conjur Kubernetes CA/O=#{conjur_account}"
        cert, key = CA.generate subject
        populate_ca_variables cert, key
      end

      def conjur_account
        Conjur.configuration.account
      end

      def ca_cert_variable
        Resource["#{conjur_account}:variable:#{id}/ca/cert"]
      end

      def ca_key_variable
        Resource["#{conjur_account}:variable:#{id}/ca/key"]
      end

      # Initialize CA from Conjur variables
      def load_ca
        ca_cert = OpenSSL::X509::Certificate.new(ca_cert_variable.secrets.last.value)
        ca_key = OpenSSL::PKey::RSA.new(ca_key_variable.secrets.last.value)
        CA.new(ca_cert, ca_key)
      end

      protected
      
      # Gets an access token for the policy role.
      def policy_token
        @policy_token ||= Conjur::API.authenticate_local "policy/#{id}"
      end

      # Stores the CA cert and key in variables.
      def populate_ca_variables cert, key
        Secret.create(resource_id: ca_cert_variable.id, value: cert.to_pem)
        Secret.create(resource_id: ca_key_variable.id, value: key.to_pem)
      end
    end
  end
end
