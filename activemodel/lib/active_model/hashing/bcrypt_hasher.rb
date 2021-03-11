require "active_model/hashing/hasher"

module ActiveModel
  module Hashing
    class BCryptHasher < Hasher
      def initialize
        load_dependency("bcrypt")
      end

      def digest(unencrypted)
        cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST : BCrypt::Engine.cost
        BCrypt::Password.create(unencrypted, cost: cost)
      end

      def check_digest(record, attribute, unencrypted)
        digest = record.public_send("#{attribute}_digest")
        BCrypt::Password.new(digest).is_password?(unencrypted)
      end
    end
  end
end
