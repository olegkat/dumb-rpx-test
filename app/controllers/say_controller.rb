require 'uri'
require 'json'
require 'net/http'
require 'net/https'
require 'cgi'

class SayController < ApplicationController
  protect_from_forgery :except => [:goodbye]
  if false
    # @@realm = 'rpxdata'
    # @@api_key = 'd63f95e12e540cfb51f9dfd56821cdd500bc66dc'
    @@realm = 'rrt'
    @@api_key = 'cf537abdd6cd066910c9afef71befc3f11c0ea23'
    @@app_id = 'bfobckokbkbkcmnpindg'
    @@rpx_host = 'rpxnow.com'
    @@rpx_host_port = '443'
    @@rpxjs_host = 'rpxnow.com'
    @@rpx_scheme = 'https'
    @@rpx_use_ssl = true

  else
    @@realm = 'rrt'
    @@api_key = '95c57546d2e151d148ba699b9c1b94381de3924f'
    @@app_id = 'fmcmdepehoodohnndbng'
    @@rpx_host = 'oleg.janrain.com'
    @@rpx_host_port = '8080'
    @@rpxjs_host = 'oleg.janrain.com:8080'
    @@rpx_scheme = 'http'
    @@rpx_use_ssl = false
  end

  @@rpx = @@rpx_host + (@@rpx_host_port.blank? ? "" : ":#{@@rpx_host_port}")
  @@rpx_js_host = "#{@@rpx_scheme}://#{@@rpx}"

  def hello
    @resp = params
  end

  def goodbye
    @rpxjs_host = @@rpxjs_host
    @rpx = @@rpx
    @api_key = @@api_key
    @app_id = @@app_id
    rpx_api = "#{@@rpx_scheme}://#{@@rpx}/api/v2/"
    rpx_api_v3 = "#{@@rpx_scheme}://#{@@rpx}/api/v3/"
    rpx_partner = "#{@@rpx_scheme}://#{@@rpx}/partner/v2/app/"
    @map_url = "#{rpx_api}map"
    @unmap_url = "#{rpx_api}unmap"
    @facebook_unlink_url = "#{rpx_api_v3}app/facebook_unlink"
    @clone_url =  "#{rpx_partner}clone"
    @set_properties_url =  "#{rpx_partner}set_properties"
    @set_status_url = "#{rpx_api}set_status"
    @activity_url = "#{rpx_api}activity"

#    if request.get? || !params[:token]
    if !params[:token]
      @signed_in = false
#      rpx_token_url = 'http://rrt.oleg.janrain.com:8080/signin/device?device=iphone'
      rpx_token_url = url_for(:controller => "say",
                              :action => "goodbye",
                              :only_path => false)
      @rpx_signin_url = "#{@@rpx_scheme}://#{@@realm}.#{@@rpx}/openid/v2/signin?token_url=#{CGI.escape(rpx_token_url)}"
      @facebook_set_app_properties_url = "#{rpx_api_v3}app/facebook_set_app_properties"

    else
      @signed_in = true
      @token = params[:token]
      profile = auth_info(@@rpx_host, @@rpx_host_port, @@rpx_use_ssl, @api_key, @token)
      @identifier = profile['identifier']

      @signout_url = url_for
      @auth_info_url = "#{rpx_api}auth_info"
      @auth_infos_url = "#{rpx_api}auth_infos"
      @get_user_data_url = "#{rpx_api}get_user_data"
      @get_contacts_url = "#{rpx_api}get_contacts"
      @facebook_stream_publish_url = "#{rpx_api}facebook/stream.publish"
    end
  end

  def setprops
    http = Net::HTTP.new('oleg.janrain.com', 8080)
    http.use_ssl = false
    path = '/api/v3/app/facebook_set_app_properties'
    data = @@api_key + "&emailDomain=janrain.com&emailPerm=true"
    data += "&uninstallURL=" + CGI::escape("http://oleg.janrain.com:2345/?mtv_app=7890")
    data += "&fbAPIKey=01404beea5667265a02f5b248ccf1f16"
    data += "&fbSecret=fa27768698b9ec83f4ec6e2b5ed7f7e7"
    data += "&fbAppID=111512492217339"
    headers = { 'Content-Type' => 'application/x-www-form-urlencoded' }
    @response = http.post(path, data, headers)
  end

  def fbpostrm
    @params = params
  end

  def fboauth
    redirect_to 'https://graph.facebook.com/oauth/authorize?client_id=111512492217339&redirect_uri=http://oleg.janrain.com/say/fboauth_cb'
  end

  def fboauth_cb
    print "\n**** code: #{params[:code]}\n"
    render :nothing => true
#    "https://graph.facebook.com/oauth/access_token?client_id=111512492217339&redirect_uri=http://oleg.janrain.com/say/fboauth_cb&client_secret=fa27768698b9ec83f4ec6e2b5ed7f7e7&code=#{params[:code]}"
  end

  def social
    @rpx = @@rpx
    @rpx_js_host = @@rpx_js_host
    @app_name = @@realm
    @app_id = @@app_id
    data = @@api_key
    @fb_publish_stream_url = "#{@@rpx_scheme}://#{@@rpx_host}/api/v2/facebook/stream.publish?#{data}"
    @timestamp = Time.now.to_i
    @primary_key = "123"
    base_string = "#{@timestamp.to_s}|#{@primary_key}"
    @signature = Base64.encode64(OpenSSL::HMAC.digest('sha256', @@api_key, base_string))
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
