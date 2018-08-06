# A CSR decorator that allows reading of the spiffe id.
#
require 'openssl'
require_relative 'extension_request_attribute_value'

module Util
  module OpenSsl
    module X509
      class CsrWithSpiffeId

        attr_reader :csr

        def initialize(csr)
          @csr = csr
        end

        # Assumes the spiffe_id is the first alt name
        #
        def spiffe_id
          @spiffe_id ||= ext_req_attr ?
            ext_req_attr_val.extension('subjectAltName').value : nil
        end

        private

        def ext_req_attr_val
          ExtensionRequestAttributeValue.new(ext_req_attr.value)
        end

        def ext_req_attr
          @csr.attributes.find { |a| a.oid == 'extReq' }
        end

      end
    end
  end
end
