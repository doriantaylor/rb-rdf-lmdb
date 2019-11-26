RSpec.describe RDF::LMDB do
  it "has a version number" do
    expect(RDF::LMDB::VERSION).not_to be nil
  end

  it_behaves_like 'an RDF::Repository' do
    # 
  end
end
