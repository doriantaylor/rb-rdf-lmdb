require 'rdf/lmdb/version'

require 'rdf'
require 'pathname'
require 'lmdb'
require 'digest'

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

      def init_lmdb dir
        @lmdb = LMDB.new dir
      end

      public

      def initialize dir = nil, **options
        init_lmdb dir
      end

      # housekeeping

      def supports? feature
      end

      # data manipulation

      def insert_statement statement
        insert_statements [statement]
      end

      def delete_statement statement
        delete_statements [statement]
      end

      def insert_statements statements
        @lmdb.transaction do
        end
      end

      def delete_statements statements
        @lmdb.transaction do
        end
      end

      # data retrieval

      def each &block
      end

      def each_subject &block
      end

      def each_predicate &block
      end

      def each_object &block
      end

      def each_graph &block
      end

      def count
      end

      def empty?
        count == 0
      end

      def query_pattern pattern, options = {}, &block
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
