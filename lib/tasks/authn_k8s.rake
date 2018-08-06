$LOAD_PATH.unshift(File.expand_path('../../..', __FILE__))
require 'app/domain/authentication/authn_k8s/conjur_ca'
require 'app/domain/conjur/certificate_resource'

namespace :authn_k8s do
  desc "Initialize CA certificates for authn-k8s webservice"
  task :ca_init, [ "service-id" ] => :environment do |t, args|
    service_name = args["service-id"] or raise "usage: rake authn_k8s:ca_init[<service-id>]"
    service_id = "#{ENV['CONJUR_ACCOUNT']}:webservice:#{service_name}"

    resource = Resource[service_id]
    Repos::ConjurCA.create(resource)
    # TODO: should this be under Conjur or is that redundant?
    cert_resource = Conjur::CertificateResource.new(resource)

    puts "Populated CA and Key of service #{service_name}"
    puts "To print values:"
    puts " conjur variable value #{cert_resource.cert_id}"
    puts " conjur variable value #{cert_resource.key_id}"
  end
end
