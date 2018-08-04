require 'app/domain/util/open_ssl/x509/csr_with_spiffe_id'
require 'app/domain/util/open_ssl/x509/quick_csr'

RSpec.describe 'Util::OpenSsl::X509::CsrWithSpiffeId' do

  let(:spiffe_id) { 'URI:spiffe://cluster.local/example' }

  let(:example_csr) do
    Util::OpenSsl::X509::QuickCsr.new(
      common_name: 'example.com',
      rsa_key: OpenSSL::PKey::RSA.new(1048),
      alt_names: [spiffe_id]
    ).request
  end

  def spiffied(csr)
    Util::OpenSsl::X509::CsrWithSpiffeId.new(csr)
  end

  context 'A CSR created as a ruby object' do
    subject(:csr) { spiffied(example_csr) }

    it 'returns the correct spiffe id' do
      expect(csr.spiffe_id).to eq spiffe_id
    end
  end

  context 'A CSR parsed from a string' do

    subject(:csr) do
      csr_str = example_csr.to_pem
      reconstructed = OpenSSL::X509::Request.new(csr_str)
      spiffied(reconstructed)
    end

    it 'returns the correct spiffe id' do
      expect(csr.spiffe_id).to eq spiffe_id
    end
  end
end
