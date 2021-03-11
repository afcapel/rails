module ActiveModel
  module Hashing
    class Hasher

      # Load bcrypt or argon2 gems only when has_secure_password is used.
      # This is to avoid ActiveModel (and by extension the entire framework)
      # being dependent on a binary libraries.
      def load_dependency(dependency)
        require dependency
      rescue LoadError
        $stderr.puts "You don't have #{dependency} installed in your application. Please add it to your Gemfile and run bundle install"
        raise
      end
    end
  end
end
