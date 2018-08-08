module Authentication
  module AuthnK8s
    class AuthenticationError < RuntimeError; end
    class CSRVerificationError < RuntimeError; end
    class ClientCertVerificationError < RuntimeError; end
    class ClientCertExpiredError < RuntimeError; end
    class NotFoundError < RuntimeError; end
    AuthenticatorNotFound = ::Util::ErrorClass.new(
      "'{0}' wasn't in the available authenticators")
    
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
      # client_cert = request.env['HTTP_X_SSL_CLIENT_CERTIFICATE']
      #
      def inject_client_cert(params, request)
        # TODO: replace this hack
        @v4_controller = :login
        
        @params = params
        @request = request
        @service_id = params[:service_id]

        validate_authenticator_enabled(@service_id)
        service_lookup # queries for webservice resource, caches, raises err if not found
        host_lookup
        authorize_host
        # ^^ all validation and objects, more ore less
        load_ca
        find_pod
        find_container

        cert = @ca.signed_cert(pod_csr, subject_altnames: [ "URI:#{spiffe_id}" ])
        install_signed_cert(cert)
      end
      
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
        load_ca
        find_pod
        find_container
        
        # Run through cert validations
        pod_certificate
        
        true
      end

      private

      def spiffe_id
        if @v4_controller == :login
          spiffe_id_login
        elsif @v4_controller == :authenticate
          spiffe_id_authenticate          
        end
      end

      def spiffe_id_login
        @spiffe_id ||= Util::OpenSsl::X509::Csr.new(pod_csr).spiffe_id
      end

      def spiffe_id_authenticate
        @spiffe_id ||= cert_spiffe_id(pod_certificate)        
      end

      def pod_name
        if @v4_controller == :login
          pod_name_login
        elsif @v4_controller == :authenticate
          pod_name_authenticate
        end
      end

      def pod_name_login
        if !@pod_name
          raise CSRVerificationError, 'CSR must contain SPIFFE ID SAN' unless spiffe_id

          _, _, namespace, _, @pod_name = URI.parse(spiffe_id).path.split("/")
          raise CSRVerificationError, 'CSR SPIFFE ID SAN namespace must match conjur host id namespace' unless namespace == k8s_namespace
        end

        @pod_name
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
      
      #TODO: pull this code out of strategy into a separate object
      #      then use that object here and in Strategy.
      #
      def validate_authenticator_enabled(service_id)
        authenticators = (@conjur_authenticators || '').split(',').map(&:strip)
        authenticator_name = "authn-k8s/#{service_id}"
        valid = authenticators.include?(authenticator_name)
        raise AuthenticatorNotFound, authenticator_name unless valid
      end

      def load_ca
        @ca = Repos::ConjurCA.ca(@service.identifier)
      end

      def find_container
        container =
          @pod.spec.containers.find { |c| c.name == k8s_container_name } ||
          @pod.spec.initContainers.find { |c| c.name == k8s_container_name }

        if container.nil?
          raise AuthenticationError, "Container #{k8s_container_name.inspect} not found in Pod #{@pod.metadata.name.inspect}"
        end

        container
      end

      def k8s_namespace
        host_id_tokens[-3]
      end

      def k8s_controller_name
        host_id_tokens[-2]
      end

      def k8s_object_name
        host_id_tokens[-1]
      end

      def k8s_container_name
        host.annotations.find { |a| a.values[:name] == 'kubernetes/authentication-container-name' }[:value] || 'authenticator'
      end

      def find_pod
        pod = K8sObjectLookup.pod_by_name(pod_name, k8s_namespace)
        unless pod
          raise AuthenticationError, "No Pod found for podname #{pod_name} in namespace #{k8s_namespace.inspect}"
        end

        # TODO: enable in pure k8s
        # unless pod.status.podIP == request_ip
        #   raise AuthenticationError, "Pod IP does not match request IP #{request_ip.inspect}"
        # end

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

      def namespace_scoped?
        k8s_controller_name == "*" && k8s_object_name == "*"
      end

      def permitted_scope?
        ["pod", "service_account", "deployment", "stateful_set", "deployment_config"].include? k8s_controller_name
      end

      def authorize_host
        unless host.role.allowed_to?("authenticate", @service)
          raise AuthenticationError, "#{host.role.id} does not have 'authenticate' privilege on #{@service.id}"
        end
      end

      def service_id
        @service_id
      end

      def service_lookup
        @service ||= Resource[
          #TODO: fix
          "#{@conjur_account}:webservice:conjur/authn-k8s/#{service_id}"
        ]
        raise NotFoundError, "Service #{service_id} not found" if @service.nil?
      end

      def host_lookup
        raise NotFoundError, "Host #{host_id} not found" if host.nil?
      end

      def host
        @host ||= Resource[host_id]
      end

      def host_id
        [ host_id_prefix, host_id_param ].compact.join('/')
      end

      def host_id_prefix
         #TODO: fix, inject account from url
         #TODO: where are the policies for this?
        "#{conjur_account}:host:conjur/authn-k8s/#{service_id}/apps"
      end

      def host_id_tokens
        host_id_param.split('/').tap do |tokens|
          raise "Invalid host id; must end with k8s_namespace/k8s_controller_name/id" unless tokens.length >= 3
        end
      end

      def host_id_param
        if @v4_controller == :login
          host_id_param_login
        elsif @v4_controller == :authenticate
          host_id_param_authenticate
        end
      end

      def host_id_param_login
        if !@host_id_param
          cn_entry = Util::OpenSsl::X509::Csr.new(pod_cert).common_name
          raise CSRVerificationError, 'CSR must contain CN' unless cn_entry
          
          @host_id_param = cn_entry.gsub('.', '/')
        end

        @host_id_param
      end

      def host_id_param_authenticate
        @host_id_param
      end

    end
  end
end
