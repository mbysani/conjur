require 'app/domain/util/open_ssl/x509/smart_cert'
require 'app/domain/util/open_ssl/x509/certificate'
require_relative 'shared_context'

RSpec.describe 'Util::OpenSsl::X509::SmartCert' do
  include_context "certificate testing"

  subject(:cert) { smart_cert(reconstructed_cert(cert_with_spiffe_id)) }

  context 'a cert with a spiffe id' do


    it "returns the SAN" do
      expect(cert.san).to eq(spiffe_id)
    end

    it "returns the common name" do
      expect(cert.common_name).to eq(common_name)
    end
  end

  context 'a cert without an alt name (spiffe id)' do

    subject(:cert) { smart_cert(reconstructed_cert(cert_without_san)) }

    it "returns nil" do
      expect(cert.san).to be_nil
    end
  end

end
