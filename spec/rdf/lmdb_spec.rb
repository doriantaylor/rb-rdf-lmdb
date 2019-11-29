RSpec.describe RDF::LMDB::Repository do
  it "has a version number" do
    expect(RDF::LMDB::VERSION).not_to be nil
  end

  #tmp = Pathname(Dir.mktmpdir)
  tmp = Pathname('/tmp/derp')

  it_behaves_like 'an RDF::Repository' do
    let :repository do
      RDF::LMDB::Repository.new tmp, mapsize: 2**30
    end

    after :each do
      repository.clear
      repository.close
    end

    after :all do
      tmp.rmtree
    end
  end
end
