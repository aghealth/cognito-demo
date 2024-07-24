# frozen_string_literal: true

class CognitoController < ApplicationController
  skip_before_action :verify_authenticity_token

  def create
    jwt = decode_jwt

    return render plain: 'Unprocessable Entity', status: :unprocessable_entity unless jwt

    user = User.find_or_create_by(email: jwt.first['email'])

    sign_in(user)
    redirect_to secure_url
  end

  private

  def decode_jwt
    token = request.headers['Authorization']&.split&.last
    return unless token

    jwks_loader = ->(options) { fetch_jwks(options) }

    JWT.decode(
      token,
      nil,
      true,
      {
        algorithms: ['RS256'],
        iss: cognito_credentials[:iss],
        verify_iss: true,
        aud: cognito_credentials[:aud],
        verify_aud: true,
        jwks: jwks_loader
      }
    )
  rescue JWT::JWKError, JWT::DecodeError
    nil
  end

  def fetch_jwks(options)
    @cached_keys = nil if options[:kid_not_found] && @cache_last_update < 5.minutes.ago.to_i

    @fetch_jwks ||=
      begin
        @cache_last_update = Time.now.to_i
        jwks_url = "#{cognito_credentials[:iss]}/.well-known/jwks.json"
        jwks_response = Net::HTTP.get(URI(jwks_url))
        jwks_hash = JSON.parse(jwks_response)

        JWT::JWK::Set.new(jwks_hash).select { |key| key[:use] == 'sig' }
      end
  end

  def cognito_credentials
    Rails.application.credentials.cognito
  end
end
