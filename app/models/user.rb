class User < ApplicationRecord
  validates :username, :session_token, :password_digest, presence: true
  validates :username, uniqueness: true, length: { minimum: 2 }
  validates :password, length: { minimum: 6 }, allow_nil: true

  after_initialize :ensure_session_token, :ensure_referral_code

    attr_reader :password

    def password=(password)
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end

    def is_password?(password)
        BCrypt::Password.new(self.password_digest).is_password?(password)
    end

    def self.find_by_credentials(username, password)
        user = User.find_by(username: username)
        return user if user && user.is_password?(password)
        nil
    end

    def reset_session_token
        self.session_token = User.generate_unique_session_token
        self.save
        self.session_token
    end

    private

    def ensure_session_token
        self.session_token ||= User.generate_unique_session_token
    end


    def self.generate_unique_session_token
        session_token = SecureRandom.urlsafe_base64(16)
        while User.find_by(session_token: session_token)
            session_token = SecureRandom.urlsafe_base64(16)
        end

        session_token
    end
end
