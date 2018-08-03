module Authentication
  module AuthnK8s
    class ConjurCA
      attr_reader :id

      # id like: conjur/authn-k8s/<cluster-name>.
      # 
      # TODO: refactor to a ConjurVariable
      #
      def initialize(id)
        @id = id
      end

      # TODO: move these to model classes?
      # Generates a CA certificate and key and store them in Conjur variables.  
      def self.create_ca_for(resource)
        cr = ::Conjur::CertificateResource.new(resource)
        ca = CA.from_subject(cr.cert_subject)
        Secret.create(resource_id: cr.cert_id, value: ca.cert.to_pem)
        Secret.create(resource_id: cr.key_id, value: ca.key.to_pem)
      end

      # Initialize CA from Conjur variables
      def self.conjur_ca(resource)
        cr = ::Conjur::CertificateResource.new(resource)
        stored_cert = Resource["#{cr.cert_id}"].last_secret.value
        stored_key = Resource["#{cr.key_id}"].last_secret.value
        ca_cert = OpenSSL::X509::Certificate.new(stored_cert)
        ca_key = OpenSSL::PKey::RSA.new(stored_key)
        CA.new(ca_cert, ca_key)
      end
    end
  end
end
