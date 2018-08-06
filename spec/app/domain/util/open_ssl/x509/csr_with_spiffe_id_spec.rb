require 'app/domain/util/open_ssl/x509/csr_with_spiffe_id'
require 'app/domain/util/open_ssl/x509/quick_csr'

RSpec.describe 'Util::OpenSsl::X509::CsrWithSpiffeId' do

  let(:spiffe_id) { 'URI:spiffe://cluster.local/example' }

  let(:csr_with_spiffe_id) do
    Util::OpenSsl::X509::QuickCsr.new(
      common_name: 'example.com',
      rsa_key: OpenSSL::PKey::RSA.new(1048),
      alt_names: [spiffe_id]
    ).request
  end

  let(:csr_without_spiffe_id) do
    Util::OpenSsl::X509::QuickCsr.new(
      common_name: 'example.com',
      rsa_key: OpenSSL::PKey::RSA.new(1048)
    ).request
  end

  # Serializes and deserializes the CSR, then wraps it in CsrWithSpiffeId
  #
  def deserialized(csr)
    csr_str = csr.to_pem
    deserialized = OpenSSL::X509::Request.new(csr_str)
    Util::OpenSsl::X509::CsrWithSpiffeId.new(deserialized)
  end


  context 'A CSR created as a ruby object' do
    subject(:csr) do
      Util::OpenSsl::X509::CsrWithSpiffeId.new(csr_with_spiffe_id)
    end

    it 'returns the correct spiffe id' do
      expect(csr.spiffe_id).to eq spiffe_id
    end
  end

  context 'A CSR parsed from a string' do

    subject(:csr) { deserialized(csr_with_spiffe_id) }

    it 'returns the correct spiffe id' do
      expect(csr.spiffe_id).to eq spiffe_id
    end
  end

  context 'A CSR parsed from a string with no alt name' do

    subject(:csr) { deserialized(csr_without_spiffe_id) }

    it 'returns nil' do
      expect(csr.spiffe_id).to be_nil
    end
  end
end
