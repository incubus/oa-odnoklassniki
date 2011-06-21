require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    class Odnoklassniki < OAuth2
      # @param [Rack Application] app standard middleware application argument
      # @param [String] client_id the application ID for your client
      # @param [String] client_secret the application secret
      def initialize(app, client_id = nil, client_secret = nil, options = {}, &block)
        client_options = {
          :site => 'http://www.odnoklassniki.ru/',
          :authorize_path => '/oauth/authorize',
          :access_token_path => 'http://api.odnoklassniki.ru/oauth/token.do'
        }
        @public_key = options[:public_key]
        super(app, :odnoklassniki, client_id, client_secret, client_options, options, &block)
      end

      protected

      def calculate_signature(params)
        str = params.sort.collect { |c| "#{c[0]}=#{c[1]}" }.join('')
        Digest::MD5.hexdigest(str + Digest::MD5.hexdigest(@access_token.token + client_secret))
      end

      def user_hash
        request_params =  {
          'method' => 'users.getCurrentUser',
          'application_key' => @public_key
        }
        request_params.merge!('access_token' => @access_token.token, 'sig' => calculate_signature(request_params))
        @user_hash ||= MultiJson.decode(client.request(:get, 'http://api.odnoklassniki.ru/fb.do', request_params))
      end

      def auth_hash
        data = user_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => data['uid'],
          'user_info' => data.merge({
            'image' => data['pic_1'],
            'urls' =>  {'Odnoklassniki' => "http://www.odnoklassniki.ru/profile/#{data['uid']}"}
          }),
          'extra' => {'user_hash' => data}
        })
      end

    end
  end
end
