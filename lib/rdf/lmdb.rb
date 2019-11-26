require 'rdf/lmdb/version'

require 'rdf'
require 'rdf/ntriples'
require 'pathname'
require 'lmdb'
require 'digest'
require 'unf' # lol unf unf unf

module RDF
  module LMDB

    # ???
    class Transaction < ::RDF::Transaction
    end

    #
    # RDF::LMDB::Repository implements a lightweight, transactional,
    # locally-attached data store using Symax LMDB.
    #
    class Repository < ::RDF::Repository
      private

      SUPPORTS = %i[graph_name].map { |s| [s, s] }.to_h.freeze

      # give us the binary hash of the initial sha256 state
      NULL_SHA256 = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      ].pack('H*').freeze

      def init_lmdb dir
        #dir = Pathname(dir).expand_path
        @lmdb = ::LMDB.new dir
        @dbs = {
          'statement' => [],
          'hash2term' => [],
          's2stmt'    => [:dupsort, :dupfixed],
          'p2stmt'    => [:dupsort, :dupfixed],
          'o2stmt'    => [:dupsort, :dupfixed],
          'g2stmt'    => [:dupsort, :dupfixed],
          'stmt2g'    => [:dupsort, :dupfixed],
        }.map do |name, flags|
          [name.to_sym, @lmdb.database(name,
            (flags + [:create]).map { |f| [f, true] }.to_h)]
        end.to_h.freeze
      end

      # everything gets normalized to NFC on the way in (i
      # consternated for a very long time about NFC vs NFKC)
      def hash_term term
        Digest::SHA256.digest term.to_ntriples.to_nfc
      end

      # note we leave the period but we nuke the newline
      def hash_statement stmt
        Digest::SHA256.digest stmt.to_ntriples.to_nfc.chomp
      end

      SPO_MAP = { subject: :s2stmt, predicate: :p2stmt, object: :o2stmt }.freeze
      SPOG_MAP = SPO_MAP.merge({ graph_name: :g2stmt }).freeze

      def add_one statement
        terms = statement.to_h
        shash = hash_statement statement

        @lmdb.transaction do
          @dbs[:statement][shash] = SPO_MAP.map do |k, d|
            term = terms[k]
            tstr = term.to_ntriples.to_nfc
            hash = hash_term term

            @dbs[d].put hash, shash          # map term hash to statement hash
            @dbs[:hash2term].put hash, tstr  # reverse-map the hash to the term

            hash
          end.join ''

          # now we have to handle the graph which will be nil if the
          # statement is just a triple
          ghash = if terms[:graph_name]
                    gh = hash_term terms[:graph_name]
                    gs = terms[:graph_name].to_ntriples.to_nfc
                    # make sure we record the term
                    @dbs[:hash2term].put gh, gs
                    gh
                  else
                    # otherwise we register the statement in the default graph
                    NULL_SHA256
                  end

          # associate the statement with the graph in both directions
          @dbs[:g2stmt].put ghash, shash
          @dbs[:stmt2g].put shash, ghash
        end
      end

      def rm_one statement, scan: true
        terms = statement.to_h
        shash = hash_statement statement
        out   = []
        @lmdb.transaction do
          # if the graph is unset then we use the null graph
          ghash = terms[:graph_name] ?
            hash_term(terms[:graph_name]) : NULL_SHA256

          # check all the graphs this statement can be found under
          graphs = []
          @dbs[:stmt2g].cursor do |c|
            c.set shash
            while val = c.next
              graphs << val[1]
            end
          end

          # this will disassociate the statement from the graph
          @dbs[:g2stmt].delete ghash, shash
          @dbs[:stmt2g].delete shash, ghash

          if graphs.size == 1 and graphs[0] == ghash
            # nuke the statement as there are no more references to it
            @dbs[:statement].delete shash

            # now we collect the terms and nuke the references
            out = SPO_MAP.each do |k, d|
              hash = hash_term terms[k]
              @dbs[d].delete hash, shash
              hash
            end
            out << ghash if ghash != NULL_SHA256
            out.uniq!

            # nuke the backreferences if scan
            clean_terms out if scan
          end
        end

        out
      end

      def clean_terms terms
        terms.map! { |t| t.is_a?(RDF::Term) ? hash_term(t) : t.to_s }
        terms.uniq.reject(NULL_SHA256).each do |hash|
          unless [:s2stmt, :p2stmt, :o2stmt, :g2stmt].any? {|d| @dbs[d][hash]}
            @dbs[:hash2term].delete hash
          end
        end
      end

      def complete! statement
        raise ArgumentError, "Statement #{statement.inspect} is incomplete" if
          statement.incomplete?
      end

      def each_whatever key, &block
        @lmdb.transaction do
          @dbs[key].each do |sh, shash|
          end
        end
      end

      def resolve_term hash
        str = @dbs[:hash2term][hash] or return
        RDF::NTriples::Reader.unserialize str
      end

      def resolve_terms string, cache: {}, hash: false
        raise ArgumentError, 'string must be a multiple of 32 bytes' unless
          string.length % 32 == 0 

        # duplicate because we're gonna start chopping on it
        string = string.dup
        seq = []
        out = {}
        until string.empty?
          seq << hash = string.slice!(0..31)
          out[hash] ||= cache[hash] || resolve_term(hash)
        end

        # if we aren't returning a hash, make sure the result is
        # returned in order
        hash ? out : out.values_at(*seq)
      end

      public

      def initialize dir = nil, **options
        init_lmdb dir
      end

      # housekeeping

      def supports? feature
        !!SUPPORTS[feature.to_s.to_sym]
      end

      # data manipulation

      def insert_statement statement
        complete! statement
        add_one statement
        nil
      end

      def delete_statement statement
        complete! statement
        rm_one statement
        nil
      end

      def insert_statements statements
        @lmdb.transaction do
          complete! statement
          statements.each { |statement| add_one statement }
        end

        nil
      end

      def delete_statements statements
        @lmdb.transaction do
          hashes = []
          statements.each do |statement|
            complete! statement
            hashes += rm_one statement, scan: false
          end

          clean_terms hashes
        end

        nil
      end

      # data retrieval

      def each &block
        return enum_for unless block_given?

        @ldmb.transaction do
          terms = {}
          @dbs[:statement].each do |shash, spo|
            terms.merge! resolve_terms
            spo = [0..31, 32..63, 64..95].map { |r| spo[r] }

            @dbs[:stmt2g].cursor do |c|
              c.set shash
            end
          end
        end
      end

      def each_subject &block
        return enum_for :each_subject unless block_given?
      end

      def each_predicate &block
        return enum_for :each_predicate unless block_given?
      end

      def each_object &block
        return enum_for :each_object unless block_given?
      end

      def each_graph &block
        return enum_for :each_graph unless block_given?
      end

      def count
        @dbs[:stmt2g].size
      end

      def empty?
        count == 0
      end

      protected

      def query_pattern pattern, options = {}, &block
        return enum_for :query_pattern, pattern, options unless block_given?

        thash = pattern.to_h.reject { |_, v| v.nil? or v.variable? }

        # if nothing in the pattern is present then this is the same
        # as #each/#each_statement
        return each if thash.empty? 

        hhash = thash.transform_values { |v| hash_term v }
        cache = {}

        if ([:subject, :predicate, :object] - thash.keys).empty?
          # if all of SPO are defined then we can just construct a
          # statement and hash it; then if G is defined on top of that
          # we can just check :stmt2g
          shash = hash_statement RDF::Statement(**thash)

          if thash[:graph_name]
            @dbs[:stmt2g].cursor do |c|
              c.set shash or return

              while rec = c.next
                # yield the quad
              end
            end
          else
            # yield just the one triple
          end
        elsif thash.keys.count == 1
          # if only a single component (e.g. :subject) is present then
          # we only need to check (e.g.) :s2stmt.
          term = thash.keys.first
          @dbs[SPOG_MAP[term]].cursor do |c|
            c.set hhash[term] or return
            while rec = c.next
              # yield the quad
            end
          end
        else
          # otherwise if there are any two of SPO present, we open a
          # cursor on both and test each for cardinality
          tmphash = thash.slice(:subject, :predicate, :object).map do |k, v|
            c = @dbs[SPOG_MAP[v]].cursor
            c.set hhash[k] or return
            [k, [c, c.count]]
          end.to_h
        end


        # which one to prioritize out of [:subject, :object,
        # :predicate]; if :graph_name is also present we can check
        # :stmt2g.

        # we open a cursor on each one and count

        # 

        # first test 
        # [:subject, :object, :predicate]

        # to get an individual statement:

        # if we have SPO then just normalize and hash it and see if we
        # have the hash

        # otherwise we check whatever subset

        # sort the searches by lowest to highest cardinality (P or G
        # will almost always be the smallest)

        # (XXX or actually we probably want to *start* with the
        # highest-cardinality we have, and then narrow it down with a
        # low-cardinality term)

        # for example O-mapping is going to actually have the least
        # statements to iterate over initially, because statement
        # objects are very likely to be unique. S is going to be
        # second-best, because resources always have at least one
        # statement. P and G could have enormous numbers of values per
        # entry.

        # then you iterate over the entries in the first, and test

        # if we have G then we should check if G has SPO
      end
    end
  end
end
