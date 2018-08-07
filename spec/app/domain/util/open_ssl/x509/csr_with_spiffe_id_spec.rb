require 'app/domain/util/open_ssl/x509/csr'
require 'app/domain/util/open_ssl/x509/quick_csr'

RSpec.shared_context "CsrHelpers" do

  let(:common_name) { 'example.com' }
  let(:spiffe_id) { 'URI:spiffe://cluster.local/example' }

  let(:csr_with_spiffe_id) do
    Util::OpenSsl::X509::QuickCsr.new(
      common_name: common_name,
      alt_names: [spiffe_id]
    ).request
  end

  let(:csr_without_spiffe_id) do
    Util::OpenSsl::X509::QuickCsr.new(common_name: 'example.com').request
  end

  # Serializes and deserializes the CSR, then wraps it in Csr This
  # is needed to accurately simulate the way CSR are actually used, because the
  # internal objects differ depending on how the CSR is created.
  #
  def reconstructed(csr)
    serialized = csr.to_pem
    deserialized = OpenSSL::X509::Request.new(serialized)
    Util::OpenSsl::X509::Csr.new(deserialized)
  end
end

RSpec.describe 'Util::OpenSsl::X509::Csr#common_name' do
  include_context "CsrHelpers"

  subject(:csr) do
    Util::OpenSsl::X509::Csr.new(csr_with_spiffe_id)
  end

  it "returns the common name" do
    expect(csr.common_name).to eq(common_name)
  end
end

RSpec.describe 'Util::OpenSsl::X509::Csr#spiffe_id' do
  include_context "CsrHelpers"

  context 'A CSR created as a ruby object' do
    subject(:csr) do
      Util::OpenSsl::X509::Csr.new(csr_with_spiffe_id)
    end

    it 'returns the correct spiffe id' do
      expect(csr.spiffe_id).to eq spiffe_id
    end
  end

  context 'A CSR parsed from a string' do

    subject(:csr) { reconstructed(csr_with_spiffe_id) }

    it 'returns the correct spiffe id' do
      expect(csr.spiffe_id).to eq spiffe_id
    end
  end

  context 'A CSR parsed from a string with no alt name' do

    subject(:csr) { reconstructed(csr_without_spiffe_id) }

    it 'returns nil' do
      expect(csr.spiffe_id).to be_nil
    end
  end

end
