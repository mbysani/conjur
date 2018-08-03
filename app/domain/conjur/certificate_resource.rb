# Represents a Conjur resource that has an associated CA, which itself consists
# of a certificate and its private key.
#
# Encapsulates logic around naming conventions for the cert and key resources,
# which can be considered child resources, as well as how to construct the
# certificate subject string.
#
module Conjur
  class CertificateResource

    def initialize(resource)
      @resource = resource
    end

    def cert_id
      "#{@resource.id}/ca/cert"
    end

    def key_id
      "#{@resource.id}/ca/key"
    end

    def cert_subject
      "/CN=#{common_name}/OU=Conjur Kubernetes CA/O=#{@resource.account}"
    end

    def common_name
      @resource.id.gsub('/', '.')
    end
  end
end
