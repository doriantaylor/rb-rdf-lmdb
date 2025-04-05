RSpec.describe RDF::LMDB::Repository do
  it "has a version number" do
    expect(RDF::LMDB::VERSION).not_to be nil
  end

  tmp = Pathname(Dir.mktmpdir)
  # tmp = Pathname('/tmp/derp')

  it_behaves_like 'an RDF::Repository' do
    let :repository do
      RDF::LMDB::Repository.new tmp, mapsize: 2**30
    end

    # XXX TODO figure out how to test the mtime within the rdf spec
    # framework (we know it works currently so no hurry lol)

    after :each do
      # comment these out if you wanna see what's in there
      repository.clear
      repository.close
    end

    after :all do
      # comment this out if yo uwant to peer into the abyss
      tmp.rmtree
    end
  end
end
