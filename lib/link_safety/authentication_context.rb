# frozen_string_literal: true

module ::LinkSafety
  # DiscourseConnect updates profile metadata inside the authentication flow.
  # Link Safety must still inspect that metadata, but a rejected profile field
  # must never make the user's authentication itself fail. Thread-local depth
  # keeps the exception-safe scope narrow and supports nested calls in tests.
  class AuthenticationContext
    KEY = :link_safety_discourse_connect_depth

    def self.with_discourse_connect
      previous = Thread.current[KEY].to_i
      Thread.current[KEY] = previous + 1
      yield
    ensure
      previous.to_i.zero? ? Thread.current[KEY] = nil : Thread.current[KEY] = previous
    end

    def self.discourse_connect?
      Thread.current[KEY].to_i.positive?
    end
  end
end
