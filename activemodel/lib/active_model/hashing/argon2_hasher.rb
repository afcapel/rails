require "active_model/hashing/hasher"

module ActiveModel
  module Hashing
    class Argon2Hasher < Hasher
      MIN_TIME_COST = 1
      MIN_MEMORY_COST = 3
      ARGON2_PREFIX = "$argon2"

      attr_accessor :memory_cost
      attr_accessor :time_cost
      attr_accessor :secret
      attr_reader :migrate

      def initialize
        load_dependency("argon2")
      end

      def migrate=(migrate)
        @migrate = migrate
        @bcrypt_hasher = migrate ? BCryptHasher.new : nil
      end

      def digest(unencrypted)
        if ActiveModel::SecurePassword.min_cost
          t_cost = MIN_TIME_COST
          m_cost = MIN_MEMORY_COST
        else
          t_cost = time_cost
          m_cost = memory_cost
        end

        hasher = Argon2::Password.new(
          t_cost: t_cost,
          m_cost: m_cost,
          secret: secret)

        hasher.create unencrypted
      end

      def check_digest(record, attribute, unencrypted)
        digest = record.public_send("#{attribute}_digest")
        should_migrate = migrate && !unencrypted_password.start_with?(ARGON2_PREFIX)

        valid_digest = if should_migrate
          @bcrypt_hasher.authenticate(record, digest, unencrypted)
        else
          Argon2::Password.verify_password(unencrypted, digest, secret)
        end

        if valid_digest && should_migrate
          record.send("#{attribute}=", unencrypted)
          record.save(validate: false)
        end

        valid_digest
      end
    end
  end
end
