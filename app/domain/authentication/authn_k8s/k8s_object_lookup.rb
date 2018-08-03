# K8sObjectLookup is used to lookup Kubernetes object metadata using 
# Kubernetes API.
module Authentication
  module AuthnK8s
    #TODO: rename to K8sApiFacade
    #
    module K8sObjectLookup
      extend self

      class K8sForbiddenError < RuntimeError; end

      # Gets the client object to the /api v1 endpoint.
      def kubectl_client
        KubeClientFactory.client
      end

      # Locates the Pod with a given IP address.
      #
      # @return nil if no such Pod exists.
      def pod_by_ip(request_ip, namespace)
        # TODO: use "status.podIP" field_selector for versions of k8s that
        # support it the current implementation is a performance optimization
        # for very early K8s versions usage of "status.podIP" field_selector on
        # versions of k8s that do not support it results in no pods returned
        # from #get_pods
        k8s_client_for_method("get_pods")
          .get_pods(field_selector: "", namespace: namespace)
          .select do |pod|
          # Just in case the filter is mis-implemented on the server side.
          pod.status.podIP == request_ip
        end.first
      end

      # Locates the Pod with a given podname in a namespace.
      #
      # @return nil if no such Pod exists.
      def pod_by_name(podname, namespace)
        k8s_client_for_method("get_pod").get_pod(podname, namespace)
      end

      # Locates pods matching label selector in a namespace.
      #
      def pods_by_label(label_selector, namespace)
        k8s_client_for_method("get_pods").get_pods(label_selector: label_selector, namespace: namespace)
      end

      # Look up an object according to the controller name. In Kubernetes, the 
      # "controller" means something like ReplicaSet, Job, Deployment, etc.
      #
      # Here, controller_name should be the underscore-ized controller, e.g.
      # "replica_set".
      #
      # @return nil if no such object exists.
      def find_object_by_name controller_name, name, namespace
        begin
          handle_object_not_found do
            invoke_k8s_method "get_#{controller_name}", name, namespace
          end
        rescue KubeException => e
          # This error message can be a bit confusing when multiple authorizers are
          # present, as is the case with GKE (IAM and k8s RBAC).
          # See: https://github.com/kubernetes/kubernetes/issues/52279
          if e.error_code == 403
            raise K8sForbiddenError, e.message
          else
            raise e
          end
        end
      end

      protected

      def invoke_k8s_method method_name, *arguments
        # orig
        k8s_client_for_method(method_name).send *( [ method_name ] + arguments )
        # rewrite
        k8s_client_for_method(method_name).send(method_name, *arguments)
      end

      # Methods move around between API versions across releases, so search the
      # client API objects to find the method we are looking for.
      def k8s_client_for_method method_name
        k8s_clients.find do |client|
          begin
            client.respond_to?(method_name)
          rescue KubeException
            false
          end
        end
      end

      # If more API versions appear, add them here.
      # List them in the order that you want them to be searched for methods.
      def k8s_clients
        @clients ||= [
          kubectl_client,
          KubeClientFactory.client(api: 'apis/apps', version: 'v1beta2'),
          KubeClientFactory.client(api: 'apis/apps', version: 'v1beta1'),
          KubeClientFactory.client(api: 'apis/extensions', version: 'v1beta1'),
          # OpenShift 3.3 DeploymentConfig
          KubeClientFactory.client(api: 'oapi', version: 'v1'),
          # OpenShift 3.7 DeploymentConfig
          KubeClientFactory.client(api: 'apis/apps.openshift.io', version: 'v1')
        ]
      end

      # returns nil if an HTTP status 404 exception occurs.
      # All other exceptions are re-raised.
      def handle_object_not_found &block
        begin
          yield
        rescue KubeException
          raise unless $!.error_code == 404
        end
      end
    end
  end
end
