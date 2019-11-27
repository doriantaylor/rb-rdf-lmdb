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

      def init_lmdb dir, **options
        dir = Pathname(dir).expand_path
        dir.mkdir unless dir.exist?
        @lmdb = ::LMDB.new dir, **options
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
      SPO = %i[subject predicate object].freeze
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

      def resolve_term hash, cache: {}, write: false
        return if hash == NULL_SHA256

        if term = cache[hash]
          return term
        end

        term = @dbs[:hash2term][hash] or return
        term = RDF::NTriples::Reader.unserialize term
        cache[hash] = term if write
        term
      end

      def split_fixed string, length
        string = string.dup
        seq = []
        until string.empty?
          seq << string.slice!(0, length)
        end
        seq
      end

      def resolve_terms string, cache: {}, write: false, hash: false
        raise ArgumentError, 'string must be a multiple of 32 bytes' unless
          string.length % 32 == 0 

        # duplicate because we're gonna start chopping on it
        string = string.dup
        seq = []
        out = {}
        until string.empty?
          seq << sha = string.slice!(0..31)
          out[sha] ||= resolve_term(sha, cache: cache, write: write)
        end

        # if we aren't returning a hash, make sure the result is
        # returned in order
        hash ? out : out.values_at(*seq)
      end

      public

      def initialize dir = nil, **options
        init_lmdb dir, **options
      end

      # housekeeping

      def supports? feature
        !!SUPPORTS[feature.to_s.to_sym]
      end

      def path
        Pathname(@lmdb.path)
      end

      def clear
        @dbs.each do |db|
          db.clear
        end
        @lmdb.database.clear
      end

      def open dir, **options
        init_lmdb dir, **options
      end

      def close
        @lmdb.close
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
          statements.each do |statement|
            complete! statement
            add_one statement
          end
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

        @lmdb.transaction do
          cache = {}
          @dbs[:statement].each do |shash, spo|
            s, p, o = resolve_terms spo, cache: cache, write: true

            next unless @dbs[:stmt2g].has? shash

            @dbs[:stmt2g].each_value shash do |val|
              graph = resolve_term val, cache: cache, write: true
              yield RDF::Statement(s, p, o, graph_name: graph)
            end
          end
        end
      end

      def each_subject &block
        return enum_for :each_subject unless block_given?
        @dbs[:s2stmt].cursor do |c|
          while (k, _ = c.next true)
            yield resolve_term k
          end
        end
      end

      def each_predicate &block
        return enum_for :each_predicate unless block_given?
        @dbs[:p2stmt].cursor do |c|
          while (k, _ = c.next true)
            yield resolve_term k
          end
        end
      end

      def each_object &block
        return enum_for :each_object unless block_given?
        @dbs[:o2stmt].cursor do |c|
          while (k, _ = c.next true)
            yield resolve_term k
          end
        end
      end

      def each_graph &block
        return enum_for :each_graph unless block_given?
        @dbs[:g2stmt].cursor do |c|
          while (k, _ = c.next true)
            next if k == NULL_SHA256
            yield RDF::Graph.new(graph_name: resolve_term(k), data: self)
          end
        end
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

        # hash of terms we get from the pattern
        thash = pattern.to_h.reject { |_, v| !v or v.variable? }

        # if nothing in the pattern is present then this is the same
        # as #each/#each_statement
        return each if thash.empty? 

        # hash of (cryptographic) hashes we generate from the terms
        hhash = thash.transform_values { |v| hash_term v }
        cache = thash.keys.map { |k| [hhash[k], thash[k]] }.to_h

        @lmdb.transaction true do
          if (SPO - thash.keys).empty?
            # if all of SPO are defined then we can just construct a
            # statement and hash it; then if G is defined on top of that
            # we can just check :stmt2g
            stmt  = RDF::Statement.new(**thash)
            shash = hash_statement stmt
            first = @dbs[:statement].get(shash) or return

            if ghash = hhash[:graph_name]
              return unless @dbs[:stmt2g].has? shash, ghash
              yield stmt
            else
              @dbs[:stmt2g].each_value shash do |ghash|
                graph = resolve_term ghash, cache: cache, write: true
                yield RDF::Statement.from(stmt, graph_name: graph)
              end
            end
          elsif thash.keys.count == 1
            # if only a single component (e.g. :subject) is present then
            # we only need to check (e.g.) :s2stmt.
            pos = thash.keys.first
            db = @dbs[SPOG_MAP[pos]]
            anchor = hhash[pos]
            return unless db.has? anchor

            db.each_value anchor do |shash|
              spo = resolve_terms @dbs[:statement][shash],
                cache: cache, write: true
              if pos == :graph_name
                graph = resolve_term anchor, cache: cache, write: true
                yield RDF::Statement(*spo, graph_name: graph)
              else
                @dbs[:stmt2g].each_value shash do |ghash|
                  graph = resolve_term ghash, cache: cache, write: true
                  yield RDF::Statement(*spo, graph_name: graph)
                end
              end
            end
          else
            # otherwise we obtain the cardinalities of the remaining
            # two elements
            cardi = hhash.slice(*SPO).map do |k, v|
              [k, @dbs[SPOG_MAP[k]].cardinality(v)]
            end
            k1, k2 = cardi.sort {|a, b| a[1] <=> b[1] }.map {|k, _| k }.take 2
            db = @dbs[SPOG_MAP[k1]]
            db.each_value hhash[k1] do |shash|
              # get the raw (sha256) hashes
              spo = @dbs[:statement][shash]
              # turn them into a (ruby) hash keyed by component
              spomap = SPO.zip(split_fixed spo, 32).to_h
              # now compare with 
              next unless hhash[k2] == spomap[k2]

              # now overwrite spo
              spo = resolve_terms spo, cache: cache, write: true

              stmt = RDF::Statement(*spo)

              if ghash = hhash[:graph_name]
                # there will only be the one statement
                return unless @dbs[:stmt2g].has? shash, ghash
                yield stmt
              else
                # otherwise there will be a statement for each graph
                @dbs[:stmt2g].each_value shash do |ghash|
                  graph = resolve_term ghash, cache: cache, write: true
                  yield RDF::Statement.from(stmt, graph_name: graph)
                end
              end
            end
          end
        end
      end
      # lol, ruby
    end
  end
end
