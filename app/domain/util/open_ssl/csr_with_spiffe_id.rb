# Read extension attributes from a CSR
#
require 'openssl'

module Util
  module OpenSsl
    class CsrWithSpiffeId

      def initialize(csr)
        @csr = csr
      end

      # Assumes the spiffe_id is the first alt name
      #
      def spiffe_id
        extensions.first
      end

      private

      # More about CSR internals:
      #
      # https://ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/ASN1.html
      # https://en.wikipedia.org/wiki/Certificate_signing_request
      # https://stackoverflow.com/questions/39842014/how-is-the-csr-signature-constructed
      #
      def ext_attributes
        @seq ||= @csr.attributes.find { |a| a.oid == 'extReq' }.value
        # other stuff below rewritten as:
      end

      def answer
        URI_from_asn1_seq(
          ext_attributes.value.find do |v|
            v.find{ |e| e.value[0].value == 'subjectAltName' }
          end.value[1].value
        )
      end

      def values_for(ext)
        #seq.value 
        seq.value.each do |v|
          v.each do |v|
            if v.value[0].value == 'subjectAltName'
              values = v.value[1].value
              break
            end
            break if values
          end
        end
        raise CSRVerificationError, "CSR must contain workload SPIFFE ID subjectAltName" if not values
        # sequence.value.
      end

      # values is an array of Asn1Data objects
      # answer is .first
      def URI_from_asn1_seq(values) 
          err = values.any? {|v| v.tag != 6 }
          raise "Unknown tag in SAN, #{v.tag} -- Available: 2 (URI)\n" if err
          values.map(&:value)
        end

          result = []
          values.each do |v|
            case v.tag
            # uniformResourceIdentifier in GeneralName (RFC5280)
            when 6
              result << "#{v.value}"
            else
              raise StandardError, "Unknown tag in SAN, #{v.tag} -- Available: 2 (URI)\n"
            end
          end
          result
        end
    end
  end
end
