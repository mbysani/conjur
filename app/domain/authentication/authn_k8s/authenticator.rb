require_relative 'host'

module Authentication
  module AuthnK8s
    class AuthenticationError < RuntimeError; end
    class ClientCertVerificationError < RuntimeError; end
    class ClientCertExpiredError < RuntimeError; end
    AuthenticatorNotFound = ::Util::ErrorClass.new(
      "'{0}' wasn't in the available authenticators"
    )
    WebserviceNotFound = ::Util::ErrorClass.new(
      "Webservice '{0}' wasn't found"
    )
    HostNotFound = ::Util::ErrorClass.new(
      "Host '{0}' wasn't found"
    )
    HostNotAuthorized = ::Util::ErrorClass.new(
      "'{0}' does not have 'authenticate' privilege on {1}"
    )
    CSRIsMissingSpiffeId = ::Util::ErrorClass.new(
      'CSR must contain SPIFFE ID SAN'
    )
    CSRNamespaceMismatch = ::Util::ErrorClass.new(
      'Namespace in SPIFFE ID must match namespace implied by common name'
    )
    PodNotFound = ::Util::ErrorClass.new(
      "No Pod found for podname '{0}' in namespace '{1}'"
    )
    ScopeNotSupported = ::Util::ErrorClass.new(
      "Resource type '{0}' identity scope is not supported in this version " +
      "of authn-k8s"
    )
    ControllerNotFound = ::Util::ErrorClass.new(
      "Kubernetes {0} {1} not found in namespace {2}"
    )
    
    class Authenticator

      #TODO: inject Resource, others
      #
      def initialize(
        conjur_authenticators: ENV['CONJUR_AUTHENTICATORS'],
        conjur_account: ENV['CONJUR_ACCOUNT']
      )
        @conjur_authenticators = conjur_authenticators
        @conjur_account = conjur_account
      end

      class InjectClientCert
        def initialize(conjur_account:, service_name:, remote_ip:, csr:, 
                       resource_model: Resource, host_model: Host,
                       k8s_facade: K8sObjectLookup,
                       conjur_ca_repo: Repos::ConjurCA)
          @conjur_account = conjur_account
          @service_name = service_name
          @remote_ip = remote_ip
          @csr = csr
          @resource_model = resource_model
          @host_model = host_model
          @k8s_facade = k8s_facade
          @conjur_ca_repo = conjur_ca_repo
        end

        def run
          validate
          create_ca_for_k8s_host
          install_signed_cert
        end

        private

        # TODO: add ip validation? validate_ip
        #
        def validate
          validate_webservice_exists
          validate_host_can_access_service
          validate_csr
          validate_pod
        end

        def validate_pod
          raise PodNotFound, spiffe_id.name, spiffe_id.namespace unless pod

          # namespace scope, no further validation needed
          return if k8s_host.namespace_scoped?

          namespace  = k8s_host.namespace
          controller = k8s_host.controller
          object     = k8s_host.object

          permitted = k8s_host.permitted_scope?
          raise ScopeNotSupported, controller unless permitted

          # permitted scope, additional checks
          raise ControllerNotFound, controller, object,
            namespace unless controller_object

          # TODO: is this needed?  can it be refactored?  Renamed?
          K8sResolver
            .for_controller(controller)
            .new(object, pod)
            .validate_pod
        end

        def controller_object
          h = k8s_host
          # TODO: the order of args here is nonstandard
          @k8s_facade.find_object_by_name(h.controller, h.object, h.namespace)
        end

        def create_ca_for_k8s_host
          @conjur_ca_repo.create(conjur_host)
        end

        def validate_webservice_exists
          raise WebserviceNotFound, svc_id unless webservice
        end

        def validate_host_can_access_service
          raise HostNotAuthorized, conjur_host.role.id,
            webservice.id unless host_can_access_service?
        end

        def host_can_access_service?
          conjur_host.role.allowed_to?("authenticate", webservice)
        end

        def validate_csr
          raise CSRIsMissingSpiffeId unless smart_csr.spiffe_id
          raise CSRNamespaceMismatch unless common_name.namespace == spiffe_id.namespace
        end

        # The fully qualified id: We should start only using "id" to mean FQIDs
        #
        def service_id
          "#{@conjur_account}:webservice:conjur/authn-k8s/#{@service_name}"
        end

        def webservice
          @webservice ||= @resource_model[service_id]
        end

        def k8s_host
          @k8s_host ||= Authentication::AuthnK8s::K8sHost.from_csr(
            account: @conjur_account,
            service_name: @service_name,
            csr: @csr
          )
        end

        def conjur_host
          @conjur_host ||= @host_model[k8s_host.conjur_host_id]
        end

        def smart_csr
          @smart_csr ||= Util::OpenSsl::X509::SmartCsr.new(csr)
        end

        def spiffe_id
          @spiffe_id ||= SpiffeId.new(smart_csr.spiffe_id)
        end

        def common_name
          @common_name ||= CommonName.new(smart_csr.common_name)
        end

        def pod
          @pod ||= @k8s_facade.pod_by_name(spiffe_id.name, spiffe_id.namespace)
        end
      end

      ############################################################# 
      #
      # BELOW HERE IS STILL TO BE CLEANED UP
      #
      ############################################################# 

      def inject_client_cert(
        service_name:,
        remote_ip:,
        csr:
      )
        validate_authenticator_enabled(service_name)
        # this stays here ^^

        find_container

        cert = @ca.signed_cert(pod_csr, subject_altnames: [ "URI:#{spiffe_id}" ])

        install_signed_cert(cert)
      end

      
      # TODO:
      # client_cert = request.env['HTTP_X_SSL_CLIENT_CERTIFICATE']
      #
      def valid?(input)
        # TODO: replace this hack
        @v4_controller = :authenticate

        # some variables that need to be used in helper methods
        @client_cert = input.password
        @service_id = input.service_id
        @host_id_param = input.username.split('/').last(3).join('/')
        
        service_lookup
        host_lookup
        authorize_host
        ca_for
        find_pod
        find_container
        
        # Run through cert validations
        pod_certificate
        
        true
      end

      private

      #TODO: pull this code out of strategy into a separate object
      #      then use that object here and in Strategy.
      #
      def validate_authenticator_enabled(service_name)
        authenticator_name = "authn-k8s/#{service_name}"
        valid = available_authenticators.include?(authenticator_name)
        raise AuthenticatorNotFound, authenticator_name unless valid
      end

      def available_authenticators
        (@conjur_authenticators || '').split(',').map(&:strip)
      end

      def ca_for(rsc)
        Repos::ConjurCA.ca(rsc)
      end

      def pod_name_authenticate
        if !@pod_name
          raise ClientCertVerificationError, 'Client certificate must contain SPIFFE ID SAN' unless spiffe_id

          _, _, namespace, _, @pod_name = URI.parse(spiffe_id).path.split("/")
          raise ClientCertVerificationError, 'Client certificate SPIFFE ID SAN namespace must match conjur host id namespace' unless namespace == k8s_namespace
        end

        @pod_name
      end
      
      #----------------------------------------
      # authn-k8s LoginController helpers
      #----------------------------------------
      
      def install_signed_cert(cert)
        exec = KubectlExec.new(@pod, container: k8s_container_name)
        response = exec.copy("/etc/conjur/ssl/client.pem", cert.to_pem, "0644")
        
        if response[:error].present?
          raise AuthenticationError, response[:error].join
        end
      end

      def pod_csr
        if !@pod_csr
          @pod_csr = OpenSSL::X509::Request.new @request.body.read
          raise CSRVerificationError, 'CSR can not be verified' unless @pod_csr.verify @pod_csr.public_key
        end

        @pod_csr
      end

      #----------------------------------------
      # authn-k8s AuthenticateController helpers
      #----------------------------------------

      def validate_cert(cert_str)
      end

      def pod_certificate
        #client_cert = request.env['HTTP_X_SSL_CLIENT_CERTIFICATE']
        raise AuthenticationError, "No client certificate provided" unless @client_cert

        if !@pod_cert
          begin
            @pod_cert ||= OpenSSL::X509::Certificate.new(@client_cert)
          rescue OpenSSL::X509::CertificateError
          end

          # verify pod cert was signed by ca
          unless @pod_cert && @ca.verify(@pod_cert)
            raise ClientCertVerificationError, 'Client certificate cannot be verified by trusted certification authority'
          end

          # verify podname SAN matches calling pod ?

          # verify host_id matches CN
          cn_entry = Util::OpenSsl::X509::SmartCsr.new(@pod_cert).common_name

          if cn_entry.gsub('.', '/') != host_id_param
            raise ClientCertVerificationError, 'Client certificate CN must match host_id'
          end

          # verify pod cert is still valid
          if @pod_cert.not_after <= Time.now
            raise ClientCertExpiredError, 'Client certificate session expired'
          end
        end

        @pod_cert
      end

      # ssl stuff

      # TODO: need this for Cert's as well as for Csr
      # SmartCert
      #
      def cert_spiffe_id(cert)
        san = Util::OpenSsl::X509::Certificate.new(cert).san
        err = "Client Certificate must contain pod SPIFFE ID subjectAltName"
        raise ClientCertVerificationError, err unless san
        san
      end
      
      #----------------------------------------
      # authn-k8s ApplicationController helpers
      #----------------------------------------
      

      def find_container
        container =
          @pod.spec.containers.find { |c| c.name == k8s_container_name } ||
          @pod.spec.initContainers.find { |c| c.name == k8s_container_name }

        if container.nil?
          raise AuthenticationError, "Container #{k8s_container_name.inspect} not found in Pod #{@pod.metadata.name.inspect}"
        end

        container
      end

      def k8s_container_name
        host.annotations.find { |a| a.values[:name] == 'kubernetes/authentication-container-name' }[:value] || 'authenticator'
      end

    end
  end
end
