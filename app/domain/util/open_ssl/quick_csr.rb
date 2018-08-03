# Currently this is useful mainly for tests, and allows you to quickly create
# CSRs with alt name extensions using a simple declarative interface
#
# TODO: Make this more robust and usable in more contexts, allow clients to set
# all of the possible basic info.  perhaps fork:
#
# https://github.com/fnando/csr
#
# The main feature we need here not available in that gem is altname extensions.

require 'openssl'

module Util
  module OpenSsl
    class QuickCsr

      # Creates a basic CSR with with alt_names extensions.
      #
      # @param common_name [String]
      # @param rsa_key [OpenSSL::PKey::RSA]
      # @param alt_names [Array<String>] Often includes the SpiffeId 
      #
      def initialize(common_name:, rsa_key:, alt_names:)
        @cn = common_name
        @rsa_key = rsa_key
        @alt_names = alt_names
      end

      # @return [OpenSSL::X509::Request]
      #
      def request
        @request ||= signed_csr
      end

      private

      def signed_csr
        OpenSSL::X509::Request.new.tap do |csr|
          add_basic_info(csr)
          add_alt_name_attrs(csr)
          sign(csr)
        end
      end

      def add_basic_info(csr)
        csr.version = 0
        csr.subject = subject
        csr.public_key = @rsa_key.public_key
      end

      def add_alt_name_attrs(csr)
        alt_name_attrs.reduce(csr) { |m, x| m.add_attribute(x); m }
      end

      def alt_name_attrs
        [
          OpenSSL::X509::Attribute.new('extReq', attribute_values),
          OpenSSL::X509::Attribute.new('msExtReq', attribute_values)
        ]
      end

      def sign(csr)
        csr.sign(@rsa_key, OpenSSL::Digest::SHA256.new)
      end

      def subject
        OpenSSL::X509::Name.new([ ['CN', @cn] ])
      end

      def attribute_values
        @attribute_values ||= 
          OpenSSL::ASN1::Set([ OpenSSL::ASN1::Sequence(extensions) ])
      end

      def extensions
        [
          ext_factory.create_extension('subjectAltName', @alt_names.join(','))
        ]
      end

      def ext_factory
        OpenSSL::X509::ExtensionFactory.new
      end
    end
  end
end

# An OpenSSL::X509::Attribute representing an extension request is a Set
# containing an array of one Sequence object, which itself holds an array of
# X509::Extension objects.  This object abstracts away all this painful
# implementation detail, allowing us to:
#
# 1. Easily create the object from an array of extensions
# 2. Look up the values of individual extensions by name
#
# asn1_data

class ExtensionRequestAttributeValue
  def initialize(extensions)
    @extensions = extensions
  end

  # NB: Both ASN1::Set and ASN1::Sequence inherit from ASN1::ASN1Data
  #
  # @return [OpenSSL::ASN1::ASN1Data]
  #
  def asn1_data
    @value ||= OpenSSL::ASN1::Set([ OpenSSL::ASN1::Sequence(@extensions) ])
  end

  # NB: ext_name and oid are the same
  #
  def value_of(ext_name)
    sequence = asn1_data.first
    ext = sequence.find { |x| x.oid == ext_name }
    ext ? ext.value : nil
  end
end
#
# TODO need to pause here and examine what actually happens when I
# look at the attribute of a real CSR

ext = OpenSSL::X509::ExtensionFactory.new.create_extension(
  'subjectAltName', 'URI:spiffe://cluster.local/namespace/foo/pod/bar')
x = ExtensionRequestAttributeValue.new( [ext] )
p x.asn1_data
__END__

p Util::OpenSsl::QuickCsr.new(
  common_name: 'example.com',
  rsa_key: OpenSSL::PKey::RSA.new(1048),
  alt_names: ['URI:spiffe://cluster.local/namespace/foo/pod/bar']
).request
