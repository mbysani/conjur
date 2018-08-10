# Represents a K8s host, typically created from a CSR or a Cert.
#
# This is not to be confused with Conjur model host.  It exists purely to
# encapsulate logic about how to translate K8s host info into a Conjur host id,
# and how to break a K8s host into its component parts: namespace, conroller,
# object
#
require 'app/domain/util/open_ssl/x509/smart_cert'
require 'app/domain/util/open_ssl/x509/smart_csr'
require_relative 'common_name'

module Authentication
  module AuthnK8s
    class K8sHost

      def self.from_csr(account:, service_name:, csr:)
        cn = Util::OpenSsl::X509::SmartCsr.new(csr).common_name
        raise ArgumentError, 'CSR must have a CN entry' unless cn

        self.new(account: account, service_name: service_name, common_name: cn)
      end

      def self.from_cert(account:, service_name:, cert:)
        cn = Util::OpenSsl::X509::SmartCert.new(cert).common_name
        raise ArgumentError, 'Certificate must have a CN entry' unless cn

        self.new(account: account, service_name: service_name, common_name: cn)
      end

      def initialize(account:, service_name:, common_name:)
        @account      = account
        @service_name = service_name
        @common_name  = CommonName.new(common_name)
      end

      def conjur_host_id
        host_id_prefix + '/' + host_name
      end

      private

      def host_id_prefix
        "#{@account}:host:conjur/authn-k8s/#{@service_name}/apps"
      end

      def host_name
        @common_name.k8s_host_name
      end

    end
  end
end
