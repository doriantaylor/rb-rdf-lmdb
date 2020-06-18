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

        #warn caller[0]

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

      DEFAULT_TX_CLASS = RDF::LMDB::Transaction

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

        # XXX trip over the old database layout for now
        dbs = @lmdb.database.keys.map(&:to_sym)
        unless dbs.empty? or dbs.include? :int2term
          err = <<-ERR.tr_s("\n ", ' ')
This version uses an updated (and incompatible) database layout.
Currently you have to dump from the old layout and reload the new one. Sorry!
          ERR
          raise ArgumentError, err
        end

        # databases are opened in a transaction, who knew
        @lmdb.transaction do # |t|
          @dbs = {
            statement: [:integerkey], # key: int; val: ints
            hash2term: [],            # key: sha256, val: int
            int2term:  [:integerkey], # key: int, val: string
            ints2stmt: [],            # key: 3x ints, val: int
            s2stmt:    [:integerkey, :dupsort, :dupfixed],
            p2stmt:    [:integerkey, :dupsort, :dupfixed],
            o2stmt:    [:integerkey, :dupsort, :dupfixed],
            g2stmt:    [:integerkey, :dupsort, :dupfixed],
            stmt2g:    [:integerkey, :dupsort, :dupfixed],
            sp2stmt:   [:dupsort, :dupfixed],
            so2stmt:   [:dupsort, :dupfixed],
            po2stmt:   [:dupsort, :dupfixed],
            # on the fence about whether or not to include graph
            # indexes; my inclination is that they would be redundant
            # gs2stmt:   [:dupsort, :dupfixed],
            # gp2stmt:   [:dupsort, :dupfixed],
            # go2stmt:   [:dupsort, :dupfixed],
          }.map do |name, flags|
            [name, @lmdb.database(name.to_s,
              **(flags + [:create]).map { |f| [f, true] }.to_h)]
          end.to_h

          # t.commit
        end
        @lmdb.sync
      end

      SPO = %i[subject predicate object].freeze
      SPO_MAP  = {
        subject:   :s2stmt,
        predicate: :p2stmt,
        object:    :o2stmt,
      }.freeze
      SPOG_MAP = SPO_MAP.merge({ graph_name: :g2stmt }).freeze
      PAIR_MAP = {
        [:subject, :predicate]    => :sp2stmt,
        [:predicate,  :object]    => :po2stmt,
        [:subject,    :object]    => :so2stmt,
        # [:graph_name, :subject]   => :gs2stmt,
        # [:graph_name, :predicate] => :gp2stmt,
        # [:graph_name, :object]    => :go2stmt,
      }.freeze

      def last_key db
        db = @dbs[db] if db.is_a? Symbol
        return nil if db.size == 0
        # the last entry in the database should be the highest number
        db.cursor { |c| c.last }.first.unpack1 ?J
      end

      def int_for term
        case term
        when nil then 0
        when RDF::Statement
          terms = term.to_a.map { |t| int_for t }
          return if terms.include? nil # the statement implicitly not here

          if raw = @dbs[:ints2stmt].get(terms.pack 'J3')
            raw.unpack1 ?J
          end
        when Hash # of integers
          if raw = @dbs[:ints2stmt].get(term.values_at(*SPO).pack 'J3')
            raw.unpack1 ?J
          end
        when RDF::Term
          thash = hash_term term
          if raw = @dbs[:hash2term].get(thash)
            raw.unpack1 ?J
          end
        when String
          # assume this is the hash string
          if raw = @dbs[:hash2term].get(term)
            raw.unpack1 ?J
          end
        end
      end

      def store_term term
        return 0 if term.nil?
        raise ArgumentError, 'must be a term' unless term.is_a? RDF::Term
        # get the hash first
        thash = hash_term term
        if ix = int_for(thash)
          return ix
        end

        # this should start with 1, not zero
        ix = (last_key(@dbs[:int2term]) || 0) + 1
        ib = [ix].pack ?J
        @dbs[:int2term].put ib, term.to_ntriples.to_nfc

        # we need the hash too to resolve the term the other way
        @dbs[:hash2term].put thash, ib

        ix # return the current index
      end

      def store_stmt statement, ints = nil
        ints ||= statement.to_h.transform_values { |v| store_term v }
        ik = ints.values_at(*SPO).pack 'J3'
        if ib = @dbs[:ints2stmt].get(ik)
          return ib.unpack1 ?J
        end

        # this should start with 1, not zero
        ix = (last_key(:statement) || 0) + 1
        ib = [ix].pack ?J

        @dbs[:statement].put ib, ik # number to triple-number
        @dbs[:ints2stmt].put ik, ib # triple-number to number

        ix # the index integer
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

      def add_one statement
        # get the integer keys for the terms and statement
        terms = statement.to_h
        ints  = terms.transform_values { |v| store_term v }
        ipack = ints.transform_values  { |v| [v].pack ?J  }
        sint  = store_stmt statement, ints
        spack = [sint].pack ?J

        # now we map the SPO indices
        SPO_MAP.each do |k, d|
          db = @dbs[d]
          ik = ipack[k]
          # note we test before inserting or lmdb will dutifully
          # create unlimited duplicate values and results will be wrong
          db.put ik, spack unless db.has? ik, spack
        end

        # now we do the pair indices
        PAIR_MAP.each do |pair, d|
          db = @dbs[d]
          ik = ipack.values_at(*pair).join
          db.put ik, spack unless db.has? ik, spack
        end

        # associate the statement with its graph; note zero is the null graph
        gint  = ints[:graph_name] || 0
        gpack = [gint].pack ?J
        @dbs[:g2stmt].put gpack, spack unless @dbs[:g2stmt].has? gpack, spack
        @dbs[:stmt2g].put spack, gpack unless @dbs[:stmt2g].has? spack, gpack
      end

      def rm_one statement, scan: true
        terms = statement.to_h
        ints  = terms.transform_values { |v| int_for v }
        # if none of the terms resolve, we don't have it
        return [] if ints.values_at(*SPO).include? nil
        # same goes for the statement
        sint   = int_for(ints) or return []
        spack  = [sint].pack ?J


        gint   = ints[:graph_name] or return []
        gpack  = [gint].pack ?J
        graphs = @dbs[:stmt2g].each_value(spack).to_a.uniq

        out  = []
        unless graphs.empty?
          # this will dissociate the statement from the graph
          @dbs[:g2stmt].delete? gpack, spack
          @dbs[:stmt2g].delete? spack, gpack

          if graphs.size == 1 and graphs.first == gpack
            # nuke the statement if this is the only instance of it
            @dbs[:statement].delete? spack
            @dbs[:ints2stmt].delete? ints.values_at(*SPO).pack('J3')

            # now we nuke the indexes

            # first the original spo
            SPO_MAP.map do |k, d|
              ib = [ints[k]].pack ?J
              @dbs[d].delete? ib, spack
              out << ints[k]
            end

            # add the graph if it is not null
            out << terms[:graph_name] if terms[:graph_name] and gint != 0

            # and now the pair map
            ipack = ints.slice(*SPO).transform_values { |v| [v].pack ?J }
            PAIR_MAP.map do |pair, d|
              ib = ipack.values_at(*pair).join
              @dbs[d].delete? ib, spack
            end
          end
        end

        # nuke any unused terms
        clean_terms out if scan

        out
      end

      def clean_terms terms
        terms.map! { |t| t.is_a?(RDF::Term) ? hash_term(t) : t.to_s }.uniq
        @lmdb.transaction do
          terms.each do |hash|
            next if hash == NULL_SHA256
            next unless ib = @dbs[:hash2term].get(hash)
            unless SPOG_MAP.values.any? {|d| @dbs[d].get ib }
              @dbs[:int2term].delete? ib
              @dbs[:hash2term].delete? hash
            end
          end
        end
      end

      def complete! statement
        raise ArgumentError, "Statement #{statement.inspect} is incomplete" if
          statement.incomplete?
      end

      def resolve_term candidate, cache: {}, write: false
        int  = nil
        term = case candidate
               when nil then return
               when Integer
                 int = candidate
                 return if int == 0
                 return cache[int] if cache[int]
                 str = [int].pack ?J
                 @dbs[:int2term][str] or return
               when String
                 int = candidate.unpack1 ?J
                 str = [int].pack ?J
                 if candidate == str
                   return if int == 0
                   return cache[int] if cache[int]
                   @dbs[:int2term][str] or return
                 else
                   return if candidate == NULL_SHA256
                   str = @dbs[:hash2term][candidate] or return
                   @dbs[:int2term][str] or return
                   int = str.unpack1 ?J
                 end
               else
                 raise ArgumentError, 'not an integer or a string'
               end

        term.force_encoding 'utf-8'

        term = RDF::NTriples::Reader.parse_object term, intern: true
        cache[int] = term if write
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
        seq = []
        out = string.unpack('J*').map do |i|
          seq << i
          j = resolve_term(i, cache: cache, write: write) 
          [i, j]
        end.to_h

        # if we aren't returning a hash, make sure the result is
        # returned in order
        hash ? out : out.values_at(*seq)
      end

      def each_maybe_with_graph has_graph = false, &block
        body = -> do
          cache = {}
          @dbs[:statement].each do |spack, spo|
            spo = resolve_terms spo, cache: cache, write: true

            @dbs[:stmt2g].each_value spack do |gpack|
              gint = gpack.unpack1 ?J
              next if has_graph and gint == 0
              graph = resolve_term gpack, cache: cache, write: true
              block.call RDF::Statement(*spo, graph_name: graph)
            end
          end
        end

        @lmdb.transaction do
          body.call
        end

        #@lmdb.active_txn ? body.call : @lmdb.transaction(true, &body)
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

        # hash of integer keys we retrieve for the terms
        ihash = thash.transform_values { |v| int_for v }
        cache = thash.keys.map { |k| [ihash[k], thash[k]] }.to_h

        body = -> do
          # if the graph is nonexistent there is nothing to show
          return if thash[:graph_name] and !ihash[:graph_name]

          if (SPO - thash.keys).empty?
            # if all of SPO are defined then we can just construct a
            # statement and hash it; then if G is defined on top of that
            # we can just check :stmt2g
            stmt  = RDF::Statement.new(**thash)
            sint  = int_for(stmt) or return
            spack = [sint].pack ?J
            first = @dbs[:statement].get(spack) or return

            # warn thash.inspect, ihash.inspect

            # note 
            if gint = ihash[:graph_name]
              gpack = [gint].pack ?J
              return unless @dbs[:stmt2g].has? spack, gpack
              yield stmt
            else
              @dbs[:stmt2g].each_value spack do |gpack|
                # return if gpack.unpack1(?J) == 0
                graph = resolve_term gpack, cache: cache, write: true
                yield RDF::Statement.from(stmt, graph_name: graph)
              end
            end
          elsif thash.keys.count == 1
            # if only a single component (e.g. :subject) is present then
            # we only need to check (e.g.) :s2stmt.
            pos = thash.keys.first
            db  = @dbs[SPOG_MAP[pos]]
            ix  = ihash[pos] or return # note ihash[pos] may be nil
            anchor = [ix].pack ?J
            return unless db.has? anchor

            db.each_value anchor do |spack|
              spo = resolve_terms @dbs[:statement][spack],
                cache: cache, write: true
              if pos == :graph_name
                yield RDF::Statement(*spo, graph_name: thash[:graph_name])
              else
                @dbs[:stmt2g].each_value spack do |gpack|
                  gint  = gpack.unpack1 ?J
                  graph = resolve_term gint, cache: cache, write: true
                  yield RDF::Statement(*spo, graph_name: graph)
                end
              end
            end
          elsif thash.keys.count == 2 and thash[:graph_name]
            pos = (thash.keys - [:graph_name]).first
            db  = @dbs[SPO_MAP[pos]]
            ix  = ihash[pos] or return
            anchor = [ix].pack ?J
            return unless db.has? anchor

            db.each_value anchor do |spack|
              spo = @dbs[:statement][spack]
              return unless @dbs[:stmt2g].has? spack, ihash[:graph_name]
              spo = resolve_terms spo
              yield RDF::Statement(*spo, graph_name: thash[:graph_name])
            end
          else
            # okay we will have either two or three terms

            # select the pair of term keys with the lowest non-zero
            # cardinality
            pair = PAIR_MAP.select do |pr, _|
              # we check for keys present as well as values (eg nil graph)
              (pr - thash.keys).empty? and ihash.values_at(*pr).none?(&:nil?)
            end.map do |pr, _|
              v = ihash.values_at(*pr).pack 'J2'
              c = @dbs[PAIR_MAP[pr]].cardinality(v)
              [c, pr]
            end.sort do |a, b|
              a.first <=> b.first
            end.reject { |x| x.first == 0 }.map(&:last).first or return

            # grab the graph if we have it
            g = resolve_term(ihash[:graph_name],
              cache: cache, write: true) if ihash[:graph_name]

            ib = ihash.values_at(*pair).pack 'J2'
            @dbs[PAIR_MAP[pair]].each_value ib do |spack|
              spo = resolve_terms @dbs[:statement][spack],
                cache: cache, write: true

              if ihash[:graph_name]
                # warn g, ihash.inspect
                gpack = [ihash[:graph_name]].pack ?J
                next unless @dbs[:stmt2g].has? spack, gpack
                yield RDF::Statement(*spo, graph_name: g)
              else
                @dbs[:stmt2g].each_value spack do |gpack|
                  gint = gpack.unpack1 ?J
                  g = resolve_term gint, cache: cache, write: true
                  yield RDF::Statement(*spo, graph_name: g)
                end
              end
            end
          end
        end

        #@lmdb.active_txn ? body.call : @lmdb.transaction(true, &body)

        ret = nil
        @lmdb.transaction do
          ret = body.call
        end

        ret
      end

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
        @lmdb.transaction do
          @dbs.each_value { |db| db.clear }
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
        @lmdb.transaction do
          statements.each do |statement|
            complete! statement
            add_one statement
          end
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
        @dbs[:int2term].cursor do |c|
          while (_, v = c.next)
            # yield RDF::NTriples::Reader.unserialize v
            v.force_encoding 'utf-8'
            yield RDF::NTriples::Reader.parse_object(v, intern: true)
          end
        end
      end

      def project_graph graph_name, &block
        return enum_for :project_graph, graph_name unless block_given?
        body = -> do
          gint  = graph_name ? int_for(graph_name) : 0
          return unless gint
          gpack = [gint].pack ?J
          cache = {}
          @dbs[:statement].each do |spack, spo|
            next unless @dbs[:stmt2g].has? spack, gpack
            spo = resolve_terms spo, cache: cache, write: true

            block.call RDF::Statement(*spo, graph_name: graph_name)
          end
        end

        @lmdb.transaction do
          body.call
        end

        #@lmdb.active_txn ? body.call : @lmdb.transaction(true, &body)
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
        int  = int_for(graph_name) or return
        pack = [int].pack ?J
        @dbs[:g2stmt].has? pack
      end

      def has_subject? subject
        raise ArgumentError, 'subject must be an RDF::Term' unless
          subject.is_a? RDF::Term
        int  = int_for(subject) or return
        pack = [int].pack ?J
        @dbs[:s2stmt].has? pack
      end
    
      def has_predicate? predicate
        raise ArgumentError, 'predicate must be an RDF::Term' unless
          predicate.is_a? RDF::Term
        int  = int_for(predicate) or return
        pack = [int].pack ?J
        @dbs[:p2stmt].has? pack
      end
    
      def has_object? object
        raise ArgumentError, 'object must be an RDF::Term' unless
          object.is_a? RDF::Term
        int  = int_for(object) or return
        pack = [int].pack ?J
        @dbs[:o2stmt].has? pack
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


      # lol, ruby
    end
  end
end
