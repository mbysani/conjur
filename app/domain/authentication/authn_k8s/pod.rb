module Authentication
  module AuthnK8s
    class Pod

      def initialize(spiffe_id)
        @spiffe_id = spiffe_id
      end

      def namespace
        parsed[2]
      end

      def name
        parsed.last
      end

      private

      def parsed
        @parsed ||= URI.parse(@spiffe_id).path.split('/')
      end
    end
  end
end
