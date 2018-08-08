# A Certificate decorator that allows reading of the spiffe id and common name
#
require 'openssl'

module Util
  module OpenSsl
    module X509
      class SmartCert < SimpleDelegator

        def san
          san_ext&.value
        end

        def common_name
          smart_subject.common_name
        end

        def smart_subject
          @subject ||= SmartName.new(subject)
        end

        private

        # def san_asn1data
        #   OpenSSL::ASN1.decode(san_ext)
        # end

        # san = subject alt name
        #
        def san_ext
          extensions.find { |e| e.oid == "subjectAltName" }
        end

      end
    end
  end
end
