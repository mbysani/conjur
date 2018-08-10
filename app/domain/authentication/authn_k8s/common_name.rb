# Represents the CN of a K8s Host.
#
require 'app/domain/util/open_ssl/x509/smart_cert'
require 'app/domain/util/open_ssl/x509/smart_csr'

module Authentication
  module AuthnK8s
    class CommonName

      def initialize(common_name)
        @common_name  = common_name
        validate!
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

      def k8s_host_name
        host_name_parts.join('/')
      end

      private

      def validate!
        return if host_name_parts.length >= 3
        raise ArgumentError, "Invalid K8s host CN: #{@common_name}. " +
              "Must end with namespace.controller.id"
      end

      def host_name_parts
        @host_name_parts ||= @common_name.split('.')
      end

    end
  end
end
