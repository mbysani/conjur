# A CSR decorator that allows reading of the spiffe id and common name.
#
require 'openssl'
require_relative 'extension_request_attribute_value'

module Util
  module OpenSsl
    module X509
      class SmartName < SimpleDelegator

        def common_name
          parts['CN']
        end

        def parts
          to_a.each(&:pop).to_h
        end

      end
    end
  end
end
