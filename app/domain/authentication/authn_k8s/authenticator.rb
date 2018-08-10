require_relative 'host'

module Authentication
  module AuthnK8s

    # TODO: delete or change these into error classes like the others with self
    #       contained messages.
    #
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
    CertInstallationError = ::Util::ErrorClass.new(
      "Cert could not be copied to pod: {0}"
    )
    ContainerNotFound = ::Util::ErrorClass.new(
      "Container {0} was not found for requesting pod"
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


      ############################################################# 
      #
      # BELOW HERE IS STILL TO BE CLEANED UP
      #
      ############################################################# 

      def inject_client_cert(service_name:, csr:)

        validate_authenticator_enabled(service_name)

        InjectClientCert.new(
          conjur_account: @conjur_account,
          service_name: service_name,
          csr: csr
        ).run
      end

      
      # TODO: Sorry John, I was not able to finish this in time.  This needs to be
      # refactored with an object analogous to InjectClientCert, perhaps ValidateCert.
      #
      # Note, however, you will NOT need to write another class as big as that one.
      #
      # Instead, first refactor an object out of InjectClientCert called something like
      # ValidatePodRequest.
      #
      # Note that we validate based on the SpiffeId and CommonName.  These can both
      # be derived from either a CSR or a Cert.  The k8s_host object already has secondary
      # constructors for both of those.  So it does _almost_ all the work for you.  The
      # spiffeId for the cert is available as `san` method on SmartCert.
      #
      # So those two (SpiffeId and CommonName) will be inputs into
      # ValidatePodRequest.  The remaining inputs needed can be found by going
      # through all the validate_XXX methods on InjectClientCert, and noting
      # any member variable objects they use (or methods that depend on member
      # variables).
      #
      # At a glance, it looks like validate_csr is the only validation method that
      # isn't shared between the two.  So InjectClientCert.validate, after refactoring,
      # will likely look something like:
      #
      # def validate
      #   @validate_pod_request.run
      #   validate_csr
      # end
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

      # NB: Constants (including classes) cannot actually be private in ruby
      # Nevertheless, we put it here to emphasize that it's job is to help its
      # containing class.  It will still be accessible directly for unit tests,
      # however, for example.
      #
      class InjectClientCert
        def initialize(conjur_account:, service_name:, csr:, 
                       resource_model: Resource, host_model: Host,
                       k8s_facade: K8sObjectLookup,
                       k8s_resolver: K8sResolver,
                       conjur_ca_repo: Repos::ConjurCA,
                       kubectl_exec: KubectlExec)
          @conjur_account = conjur_account
          @service_name = service_name
          @csr = csr
          @resource_model = resource_model
          @host_model = host_model
          @k8s_facade = k8s_facade
          @conjur_ca_repo = conjur_ca_repo
        end

        def run
          validate
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
          validate_container
        end

        # TODO: This is _ok_.  It really looks like there's another small object here,
        #       though.   Ie, 
        #
        #           PodValidation.new(k8s_host, resolver, spiffe_id)
        #
        #       As we discussed, that would cleanup up the local vars, and make this 
        #       really clean.
        #
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
          @k8s_resolver
            .for_controller(controller)
            .new(object, pod)
            .validate_pod
        end

        def validate_container
          container =
            pod.spec.containers.find { |c| c.name == container_name } ||
            pod.spec.initContainers.find { |c| c.name == container_name }

          raise ContainerNotFound, container_name unless container
        end

        def install_signed_cert
          exec = @kubectl_exec.new(pod, container: container_name)
          resp = exec.copy("/etc/conjur/ssl/client.pem", cert.to_pem, "0644")
          raise CertInstallationError, resp[:error] if response[:error].present?
        end

        def ca_for_webservice
          @conjur_ca_repo.ca(conjur_host)
        end

        def cert_to_install
          ca_for_webservice.signed_cert(
            @csr, 
            subject_altnames: [ spiffe_id.to_s ]
          )
        end

        def container_name
          name = 'kubernetes/authentication-container-name'
          annotation = host.annotations.find { |a| a.values[:name] == name }
          annotation[:value] || 'authenticator'
        end

        def controller_object
          h = k8s_host
          # TODO: the order of args here is nonstandard
          @k8s_facade.find_object_by_name(h.controller, h.object, h.namespace)
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
    end
  end
end
