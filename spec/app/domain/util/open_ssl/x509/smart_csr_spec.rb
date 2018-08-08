require 'app/domain/util/open_ssl/x509/smart_csr'
require 'app/domain/util/open_ssl/x509/quick_csr'
require_relative 'shared_context'

RSpec.describe 'Util::OpenSsl::X509::SmartCsr#common_name' do
  include_context "certificate testing"

  subject(:csr) { smart_csr(reconstructed_csr(csr_with_spiffe_id)) }

  it "returns the common name" do
    expect(csr.common_name).to eq(common_name)
  end
end

RSpec.describe 'Util::OpenSsl::X509::SmartCsr#spiffe_id' do
  include_context "certificate testing"

  context 'A CSR created as a ruby object' do
    subject(:csr) { smart_csr(csr_with_spiffe_id) }

    it 'returns the correct spiffe id' do
      expect(csr.spiffe_id).to eq spiffe_id
    end
  end

  context 'A CSR parsed from a string' do

    subject(:csr) { smart_csr(reconstructed_csr(csr_with_spiffe_id)) }

    it 'returns the correct spiffe id' do
      expect(csr.spiffe_id).to eq spiffe_id
    end
  end

  context 'A CSR parsed from a string with no alt name' do

    subject(:csr) { smart_csr(reconstructed_csr(csr_without_spiffe_id)) }

    it 'returns nil' do
      expect(csr.spiffe_id).to be_nil
    end
  end
end
