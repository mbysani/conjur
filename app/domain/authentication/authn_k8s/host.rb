require 'app/domain/util/open_ssl/x509/smart_cert'
require 'app/domain/util/open_ssl/x509/smart_csr'

module Authentication
  module AuthnK8s
    class Host

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
        @common_name  = common_name
        validate!
      end

      def host_id
        host_id_prefix + '/' + host_name
      end

      def namespace
        host_name_parts[-3]
      end

      def controller
        host_name_parts[-2]
      end

      def object
        host_name_parts[-1]
      end

      private

      def validate!
        return if host_name_parts.length >= 3
        raise ArgumentError, "Invalid K8s host CN: #{@common_name}. " +
              "Must end with namespace.controller.id"
      end

      def host_id_prefix
        "#{@account}:host:conjur/authn-k8s/#{@service_name}/apps"
      end

      def host_name
        host_name_parts.join('/')
      end

      def host_name_parts
        @host_name_parts ||= @common_name.split('.')
      end

    end
  end
end
