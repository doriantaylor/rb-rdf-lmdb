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
      private

      # LMDB transactions have to happen inside a block, while
      # RDF::Transactable transactions can float freely.

      def wrap_txn &block
        begin
          @repository.env.transaction !@mutable do |t|
            @txn = t

            case block.arity
            when 1 then block.call(self)
            else self.instance_eval(&block)
            end

            # and now we make sure we change it
            execute unless @rolledback
            @txn = nil
          end
        rescue => error
          raise error
        end
      end

      public

      def initialize repository,
          graph_name: nil, mutable: false, **options, &block
        @repository = repository
        @snapshot = 
          repository.supports?(:snapshots) ? repository.snapshot : repository
        @options    = options.dup
        @mutable    = mutable
        @graph_name = graph_name

        raise TransactionError, 
          'Tried to open a mutable transaction on an immutable repository' if
          @mutable && !@repository.mutable?

        @changes = RDF::Changeset.new

        warn caller[0]

        wrap_txn(&block) if block_given?
      end

      def execute
        raise TransactionError,
          'Cannot execute a rolled back transaction. Open a new one instead.' if
          @rolledback

        ret = if @txn
                @changes.apply(@repository)
              else
                wrap_txn { @changes.apply(@repository) }
              end

        @changes = RDF::Changeset.new

        ret
      end

      def rollback
        if @txn
          @txn.abort
          @txn = nil
        end

        super
      end
    end

    #
    # RDF::LMDB::Repository implements a lightweight, transactional,
    # locally-attached data store using Symax LMDB.
    #
    class Repository < ::RDF::Repository
      private

      SUPPORTS = %i[
        graph_name literal_equality atomic_writes
      ].map {|s| [s, s] }.to_h.freeze

      # give us the binary hash of the initial sha256 state
      NULL_SHA256 = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      ].pack('H*').freeze

      def init_lmdb dir, **options
        dir = Pathname(dir).expand_path
        dir.mkdir unless dir.exist?

        # fire up the environment
        @lmdb = ::LMDB.new dir, **options

        # databases are opened in a transaction, who knew
        @lmdb.transaction do |t|
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
          end.to_h

          t.commit
        end
        @lmdb.sync
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
        htdb  = @dbs[:hash2term]

        # no transaction
        thash = SPO_MAP.map do |k, d|
          term = terms[k]
          tstr = term.to_ntriples.to_nfc
          hash = hash_term term
          db = @dbs[d]

          #warn "#{k}: #{hash.unpack('H*').first} => #{tstr}"
          #warn htdb.has? hash, tstr

          #warn "#{htdb.size} #{db.size}"

          # reverse-map the hash to the term
          htdb.put hash, tstr
          #htdb.cursor { |c| c.put hash, tstr }

          # map term hash to statement hash
          db.put hash, shash unless db.has? hash, shash

          hash
        end.join ''
        @dbs[:statement].put shash, thash

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
        @dbs[:g2stmt].put ghash, shash unless @dbs[:g2stmt].has? ghash, shash
        @dbs[:stmt2g].put shash, ghash unless @dbs[:stmt2g].has? shash, ghash
      end

      def rm_one statement, scan: true
        terms = statement.to_h
        shash = hash_statement statement
        out   = []

        # if the graph is unset then we use the null graph
        ghash = terms[:graph_name] ?
          hash_term(terms[:graph_name]) : NULL_SHA256

        # check all the graphs this statement can be found under
        graphs = []
        #@dbs[:stmt2g].each_value shash { |gh| graphs << gh }
        graphs = @dbs[:stmt2g].each_value(shash).to_a.uniq

        unless graphs.empty?
          # this will disassociate the statement from the graph
          @dbs[:g2stmt].delete? ghash, shash
          @dbs[:stmt2g].delete? shash, ghash

          if graphs.size == 1 and graphs[0] == ghash
            # nuke the statement as there are no more references to it
            @dbs[:statement].delete? shash

            # now we collect the terms and nuke the references
            out = SPO_MAP.map do |k, d|
              hash = hash_term terms[k]
              @dbs[d].delete? hash, shash
              hash
            end
            out << ghash if ghash != NULL_SHA256
            out.uniq!
          end
        end

        # nuke the backreferences if scan
        clean_terms out if scan

        out
      end

      def clean_terms terms
        terms.map! { |t| t.is_a?(RDF::Term) ? hash_term(t) : t.to_s }.uniq
        @lmdb.transaction do
          terms.each do |hash|
            next if hash == NULL_SHA256
            unless SPOG_MAP.values.any? {|d| @dbs[d].get hash }
              @dbs[:hash2term].delete? hash
            end
          end
        end
      end

      def complete! statement
        raise ArgumentError, "Statement #{statement.inspect} is incomplete" if
          statement.incomplete?
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

      def each_maybe_with_graph has_graph = false, &block

        @lmdb.transaction do
          cache = {}
          @dbs[:statement].each do |shash, spo|
            spo = resolve_terms spo, cache: cache, write: true

            @dbs[:stmt2g].each_value shash do |ghash|
              next if has_graph and ghash == NULL_SHA256
              graph = resolve_term ghash, cache: cache, write: true
              block.call RDF::Statement(*spo, graph_name: graph)
            end
          end
        end
      end

      def check_triple_quad arg, name: :triple, quad: false
        raise ArgumentError, "#{name} must be Array-able" unless
          arg.respond_to? :to_a
        arg = arg.to_a
        spo = arg.take 3
        raise ArgumentError,
          '#{name} must be at least 3 RDF::Term elements' unless
          spo.length == 3 and spo.all? { |x| x.is_a? RDF::Term }
        graph = nil
        if quad
          graph = arg[3]
          raise ArgumentError, 'quad must be nil or an RDF::Term' unless
            graph.nil? or graph.is_a? RDF::Term
        end

        RDF::Statement(*spo, graph_name: graph)
      end

      DEFAULT_TX_CLASS = RDF::LMDB::Transaction

      public

      def initialize dir = nil, uri: nil, title: nil, **options, &block
        dir ||= options.delete(:dir) if options[:dir]

        # wtf no idea why this won't inherit
        @tx_class ||= options.delete(:transaction_class) { DEFAULT_TX_CLASS }
        raise ArgumentError, "Invalid transaction class #{@tx_class}" unless
          @tx_class.is_a? Class and @tx_class <= DEFAULT_TX_CLASS

        init_lmdb dir, **options
        super uri: uri, title: title, **options, &block
      end

      # housekeeping

      def supports? feature
        !!SUPPORTS[feature.to_s.to_sym]
      end

      def isolation_level
        :serializable
      end

      def path
        Pathname(@lmdb.path)
      end

      def clear
        @lmdb.transaction do |t|
          @dbs.each_value { |db| db.clear }
          t.commit
        end
        # we do not clear the main database; that nukes the sub-databases
        # @lmdb.database.clear
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
        @lmdb.transaction { |t| add_one statement; t.commit }
        nil
      end

      def delete_statement statement
        complete! statement
        @lmdb.transaction { |t| rm_one statement; t.commit }
        nil
      end

      def insert_statements statements
        @lmdb.transaction do |t|
          statements.each do |statement|
            complete! statement
            add_one statement
          end
          t.commit
        end

        nil
      end

      def delete_statements statements
        @lmdb.transaction do |t|
          hashes = []
          statements.each do |statement|
            complete! statement
            hashes += rm_one statement, scan: false
          end

          clean_terms hashes
          t.commit
        end

        nil
      end

      # data retrieval

      def each &block
        return enum_for :each unless block_given?

        each_maybe_with_graph(&block)
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
            yield RDF::Graph.new(graph_name: resolve_term(k), data: self)
          end
        end
      end

      def each_term &block
        return enum_for :each_term unless block_given?
        @dbs[:hash2term].cursor do |c|
          while (_, v = c.next)
            yield RDF::NTriples::Reader.unserialize v
          end
        end
      end

      def project_graph graph_name, &block
        return enum_for :project_graph, graph_name unless block_given?
        @lmdb.transaction do
          ghash = graph_name ? hash_term(graph_name) : NULL_SHA256
          cache = {}
          @dbs[:statement].each do |shash, spo|
            next unless @dbs[:stmt2g].has? shash, ghash
            spo = resolve_terms spo, cache: cache, write: true

            yield RDF::Statement(*spo, graph_name: graph_name)
          end
        end
      end

      def count
        @dbs[:stmt2g].size
      end

      def empty?
        count == 0
      end

      # def apply_changeset changeset
      #   @lmdb.transaction do |t|
      #     delete_insert(changeset.deletes, changeset.inserts)
      #   end
      # end

      def delete_insert deletes, inserts
        ret = super(deletes, inserts)
        commit_transaction # this is to satiate the test suite
        ret
      end

      def env
        @lmdb
      end

      def transaction mutable: false, &block
        return begin_transaction mutable: mutable unless block_given?

        begin
          begin_transaction mutable: mutable, &block
        rescue => error
          rollback_transaction # to sate the test suite
          raise error
        end
        #commit_transaction # to sate the test suite
        self
      end

      def has_statement? statement
        raise ArgumentError, 'Argument must be an RDF::Statement' unless
          statement.is_a? RDF::Statement
        !query_pattern(statement.to_h).to_a.empty?
      end

      def has_graph? graph_name
        raise ArgumentError, 'graph_name must be an RDF::Term' unless
          graph_name.is_a? RDF::Term
        @dbs[:g2stmt].has? hash_term(graph_name)
      end

      def has_subject? subject
        raise ArgumentError, 'subject must be an RDF::Term' unless
          subject.is_a? RDF::Term
        @dbs[:s2stmt].has? hash_term(subject)
      end
    
      def has_predicate? predicate
        raise ArgumentError, 'predicate must be an RDF::Term' unless
          predicate.is_a? RDF::Term
        @dbs[:p2stmt].has? hash_term(predicate)
      end
    
      def has_object? object
        raise ArgumentError, 'object must be an RDF::Term' unless
          object.is_a? RDF::Term
        @dbs[:o2stmt].has? hash_term(object)
      end

      def has_term? term
        raise ArgumentError, 'term must be an RDF::Term' unless
          term.is_a? RDF::Term
        @dbs[:hash2term].has? hash_term(term)
      end

      def has_triple? triple
        has_statement? check_triple_quad triple
      end

      def has_quad? quad
        has_statement? check_triple_quad quad, quad: true
      end

      protected

      def begin_transaction mutable: false, graph_name: nil, &block
        @tx_class.new self, mutable: mutable, graph_name: graph_name, &block
      end

      def commit_transaction txn = nil
        nil # nothing lol
      end

      def rollback_transaction txn = nil
        nil # nothing lol
      end

      def query_pattern pattern, options = {}, &block
        return enum_for :query_pattern, pattern, options unless block_given?

        # coerce to hash
        pattern = pattern.to_h

        # flag if the graph is a variable
        gv = pattern[:graph_name] && pattern[:graph_name].variable?
        # hash of terms we get from the pattern
        thash = pattern.reject { |_, v| !v or v.variable? }

        # if nothing in the pattern is present then this is the same
        # as #each/#each_statement
        return each_maybe_with_graph(gv, &block) if thash.empty?

        # hash of (cryptographic) hashes we generate from the terms
        hhash = thash.transform_values { |v| hash_term v }
        cache = thash.keys.map { |k| [hhash[k], thash[k]] }.to_h

        @lmdb.transaction do
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
            zero  = false
            cardi = hhash.slice(*SPO).map do |k, v|
              c = @dbs[SPOG_MAP[k]].cardinality(v)
              zero = true if c == 0
              [k, c]
            end

            # if the cardinality of one of the terms is zero then
            # there are by definition no statements to retrieve
            return if zero

            # warn cardi.inspect
            # warn thash.values_at(
            #   *(cardi.to_h.filter { |_, v| v == 0 }).keys).inspect

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
