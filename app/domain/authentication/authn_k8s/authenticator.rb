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

      # TODO: pass these in directly instead of params/request
      #
      # request.remote_ip
      # request.body.read (pod_csr)
      #
      def inject_client_cert(
        service_name:,
        remote_ip:,
        csr:
      )
        validate_authenticator_enabled(service_name)
        webservice = service_resource(service_name)

        # these will becoe private meths on the object i'll create
        kube_host = k8s_host(service_name, csr)
        conjur_host = Host[kube_host.conjur_host_id]
        smart_csr = Util::OpenSsl::X509::SmartCsr.new(csr)
        spiffe_id = SpiffeId.new(smart_csr.spiffe_id)
        # this won't happen het because it will be a lazy method
        pod = K8sObjectLookup.pod_by_name(spiffe_id.name, spiffe_id.namespace)

        validate_host_can_access_service(conjur_host, webservice)
        validate_csr(smart_csr)
        # validate ip

        create_ca(conjur_host)

        find_pod(host, smart_csr.spiffe_id)
        find_container

        cert = @ca.signed_cert(pod_csr, subject_altnames: [ "URI:#{spiffe_id}" ])

        install_signed_cert(cert)
      end

      def k8s_host(service_name, csr)
        Authentication::AuthnK8s::K8sHost.from_csr(
          account: @conjur_account,
          service_name: service_name,
          csr: csr
        )
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

      def validate_host_can_access_service(conjur_host, webservice)
        has_access = conjur_host.role.allowed_to?("authenticate", webservice)
        raise HostNotAuthorized, conjur_host.role.id, webservice.id unless has_access
      end

      def service_resource(service_name)
        svc_id = "#{@conjur_account}:webservice:conjur/authn-k8s/#{service_name}"
        service_resource = Resource[svc_id]
        raise WebserviceNotFound, svc_id unless service_resource
      end

      #TODO: pull this code out of strategy into a separate object
      #      then use that object here and in Strategy.
      #
      def validate_authenticator_enabled(service_name)
        authenticator_name = "authn-k8s/#{service_name}"
        valid = available_authenticators.include?(authenticator_name)
        raise AuthenticatorNotFound, authenticator_name unless valid
      end

      def validate_csr(smart_csr)
        raise CSRIsMissingSpiffeId unless smart_csr.spiffe_id
        spiffe_id = SpiffeId.new(smart_csr.spiffe_id)
        common_name = CommonName.new(smart_csr.common_name)
        raise CSRNamespaceMismatch unless common_name.namespace == spiffe_id.namespace
      end

      def validate_pod(pod, spiffe_id)

        raise PodNotFound, spiffe_id.name, spiffe_id.namespace unless pod

        if namespace_scoped?
          @pod = pod
        elsif permitted_scope?
          controller_object = K8sObjectLookup.find_object_by_name k8s_controller_name, k8s_object_name, k8s_namespace
          unless controller_object
            err = "Kubernetes #{k8s_controller_name} "\
              "#{k8s_object_name.inspect} not found in namespace "\
              "#{k8s_namespace.inspect}"
            raise AuthenticationError, err
          end

          resolver = K8sResolver
            .for_controller(k8s_controller_name)
            .new(controller_object, pod)
          # May raise K8sResolver#ValidationError
          resolver.validate_pod

          @pod = pod
        else
          raise AuthenticationError, "Resource type #{k8s_controller_name} identity scope is not supported in this version of authn-k8s"
        end
      end

      def available_authenticators
        (@conjur_authenticators || '').split(',').map(&:strip)
      end

      def create_ca(conjur_host)
        Repos::ConjurCA.create(conjur_host)
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

      def namespace_scoped?
        k8s_controller_name == "*" && k8s_object_name == "*"
      end

      def permitted_scope?
        ["pod", "service_account", "deployment", "stateful_set", "deployment_config"].include? k8s_controller_name
      end


      def host
        @host ||= Resource[host_id]
      end
    end
  end
end
