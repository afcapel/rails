require "cases/helper"
require "models/user"
require "models/visitor"

class Argon2HasherTest < ActiveModel::TestCase
  setup do
    ActiveModel::SecurePassword.hasher = :argon2
    @original_min_cost = ActiveModel::SecurePassword.min_cost
    @user = User.new
  end

  teardown do
    ActiveModel::SecurePassword.hasher = :bcrypt
    ActiveModel::SecurePassword.min_cost = @original_min_cost
  end

  test "cost defaults to argon2 default cost when min_cost is false" do
    ActiveModel::SecurePassword.min_cost = false

    @user.password = "secret"
    assert_equal 16, memory_cost_for(@user.password_digest)
    assert_equal 2, time_cost_for(@user.password_digest)
  end

  test "cost can be set to argon2 min cost to speed up tests" do
    ActiveModel::SecurePassword.min_cost = true

    @user.password = "secret"

    assert_equal ActiveModel::Hashing::Argon2Hasher::MIN_MEMORY_COST, memory_cost_for(@user.password_digest)
    assert_equal ActiveModel::Hashing::Argon2Hasher::MIN_TIME_COST, time_cost_for(@user.password_digest)
  end

  test "can use a master secret key" do
    ActiveModel::SecurePassword.hasher.secret = "master secret"

    @user.password = "secret"
    assert_equal @user, @user.authenticate("secret")

    ActiveModel::SecurePassword.hasher.secret = "non master secret"
    refute @user.authenticate("secret")
  end

  private

  # Argon2 hashes have the format "$argon2id$v=19$m=65536,t=2,p=HASH" where:
  # m is the 2^memory_cost
  # t is the time cost
  def memory_cost_for(digest)
    digest =~ /m=(\d+)/
    Math.log2($1.to_i).round
  end

  def time_cost_for(digest)
    digest =~ /t=(\d+)/
    $1.to_i
  end
end
