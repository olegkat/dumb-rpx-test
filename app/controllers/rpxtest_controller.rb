require 'uri'
require 'json'
require 'net/http'
require 'net/https'
require 'cgi'

class RpxtestController < ApplicationController
  protect_from_forgery :except => [:api]

  def api
    @api = RPX[:api]
    @api_key = RPX[:api_key]

    if !params[:token]
      @signed_in = false
      rpx_token_url = url_for(:controller => "rpxtest",
                              :action => "api",
                              :only_path => false)
      @rpx_signin_url = RPX[:signin_url] + "?token_url=#{CGI.escape(rpx_token_url)}"
      @rpx_embed_url = RPX[:embed_url] + "?token_url=#{CGI.escape(rpx_token_url)}"

    else
      @signed_in = true

      if request.get?
        print "**** WARNING: RPX server uses GET to submit the token.\n"
      end

      @token = params[:token]
      profile = auth_info(RPX[:api_host], RPX[:api_port], (RPX[:api_scheme] == 'https'), RPX[:api_key], @token)
      @identifier = profile['identifier']

      @signout_url = url_for
    end
  end

  def social
    @app_name = RPX[:realm]
    @timestamp = Time.now.to_i
    @primary_key = "123"
    base_string = "#{@timestamp.to_s}|#{@primary_key}"
    @signature = Base64.encode64(OpenSSL::HMAC.digest('sha256', RPX[:api_key], base_string))
    @signature.chomp!
  end

  protected

  def auth_info(host, port, use_ssl, api_key, token)
    http = Net::HTTP.new(host, port)
    http.use_ssl = use_ssl
    path = '/api/v2/auth_info'
    data = "apiKey=#{api_key}&token=#{token}&format=json"
    headers = { 'Content-Type' => 'application/x-www-form-urlencoded' }

    response = http.post(path, data, headers)
    result = JSON.parse(response.body)

    if result['stat'] and result['stat'] == 'ok'
      return result['profile']
    end

    return nil
  end
end
