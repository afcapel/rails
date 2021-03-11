require "cases/helper"
require "models/user"
require "models/visitor"

class BCryptHasherTest < ActiveModel::TestCase
  setup do
    @original_min_cost = ActiveModel::SecurePassword.min_cost
    @user = User.new
  end

  teardown do
    ActiveModel::SecurePassword.min_cost = @original_min_cost
  end

  test "Password digest cost defaults to bcrypt default cost when min_cost is false" do
    ActiveModel::SecurePassword.min_cost = false

    @user.password = "secret"
    assert_equal BCrypt::Engine::DEFAULT_COST, @user.password_digest.cost
  end

  test "Password digest cost honors bcrypt cost attribute when min_cost is false" do
    original_bcrypt_cost = BCrypt::Engine.cost
    ActiveModel::SecurePassword.min_cost = false
    BCrypt::Engine.cost = 5

    @user.password = "secret"
    assert_equal BCrypt::Engine.cost, @user.password_digest.cost
  ensure
    BCrypt::Engine.cost = original_bcrypt_cost
  end

  test "Password digest cost can be set to bcrypt min cost to speed up tests" do
    ActiveModel::SecurePassword.min_cost = true

    @user.password = "secret"
    assert_equal BCrypt::Engine::MIN_COST, @user.password_digest.cost
  end
end
