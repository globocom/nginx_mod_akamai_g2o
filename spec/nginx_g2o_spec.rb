require 'rest-client'
require 'net/http'
require 'digest'
require 'base64'
require 'openssl'

RSpec::Matchers.define :be_a_multiple_of do |expected|
  match do |actual|
    actual % expected == 0
  end
end

RSpec::Matchers.define :respond_with do |expected|
  match do |actual|
    actual.is_a?(expected)
  end
end

describe 'nginx mod' do
  before :all do
    nginx_dir = Dir['nginx-*'][0]
    @nginx_pid = spawn "#{nginx_dir}/prefix/sbin/nginx"
    sleep 1
  end

  after :all do
    Process.kill "TERM", @nginx_pid
  end

  describe 'G2O headers' do
    before :each do
      @uri = URI.parse('http://localhost:8080/download/stuff.html')
    end

    def g2o_data_header(options = {})
      time = (options[:time] or Time.now)
      token = (options[:token] or "token")
      version = (options[:version] or 3)

      "#{version}, 69.31.17.132, 80.169.32.154, #{time.to_i}, 13459971.1599924223, #{token}"
    end

    it 'should allow access to content with correct G2O headers' do
      data = g2o_data_header
      sign = sign_data(data)

      get(data, sign).should respond_with(Net::HTTPOK)
    end

    it 'should disallow access to content with time more than 30 seconds into the future' do
      data = g2o_data_header(:time => Time.now + 31)
      sign = sign_data(data)

      get(data, sign).should respond_with(Net::HTTPForbidden)
    end

    it 'should allow access to content with time less than 30 seconds into the future' do
      data = g2o_data_header(:time => Time.now + 29)
      sign = sign_data(data)

      get(data, sign).should respond_with(Net::HTTPOK)
    end

    it 'should disallow access to content with time more than 30 seconds into the past' do
      data = g2o_data_header(:time => Time.now - 31)
      sign = sign_data(data)

      get(data, sign).should respond_with(Net::HTTPForbidden)
    end

    it 'should allow access to content with time less than 30 seconds into the past' do
      data = g2o_data_header(:time => Time.now - 29)
      sign = sign_data(data)

      get(data, sign).should respond_with(Net::HTTPOK)
    end

    it 'should disallow access to content with wrong signature' do
      data = g2o_data_header
      sign = "wrong sig"

      get(data, sign).should respond_with(Net::HTTPForbidden)
    end

    it 'should disallow access to content if using wrong token' do
      data = g2o_data_header(:token => "wrong_token")
      sign = sign_data(data)

      get(data, sign).should respond_with(Net::HTTPForbidden)
    end

    it 'should disallow access to content if data header is badly formated' do
      data = "3, 69.31.17.132"
      sign = sign_data(data)
      get(data, sign).should respond_with(Net::HTTPForbidden)
    end

    it 'should disallow access to content if using wrong version' do
      data = g2o_data_header(:version => 2)
      sign = sign_data(data)
      get(data, sign).should respond_with(Net::HTTPForbidden)
    end

    context "with path that accepts token1 token" do
      before do
        @uri = URI.parse('http://localhost:8080/allow_token1/stuff.html')
      end

      it 'should allow access to content with token1' do
        data = g2o_data_header(:token => "token1")
        sign = sign_data(data, :key => "a_different_password")

        get(data, sign).should respond_with(Net::HTTPOK)
      end

      it 'should disallow access to content with token2' do
        data = g2o_data_header(:token => "token2")
        sign = sign_data(data, :key => "a_different_password")

        get(data, sign).should respond_with(Net::HTTPForbidden)
      end
    end

    context "with path that has g2o turned off" do
      before do
        @uri = URI.parse('http://localhost:8080/allow_all/stuff.html')
      end

      it 'should allow all requests' do
        get.should respond_with(Net::HTTPOK)
      end
    end

    context "using variables to set token and password into the conf" do
      before do
        @uri = URI.parse('http://localhost:8080/using_vars/stuff.html')
      end

      it 'should allow access to content with correct G2O headers' do
        data = g2o_data_header
        sign = sign_data(data)

        get(data, sign).should respond_with(Net::HTTPOK)
      end

      it 'should disallow access to content if using wrong token' do
        data = g2o_data_header(:token => "wrong_token")
        sign = sign_data(data)

        get(data, sign).should respond_with(Net::HTTPForbidden)
      end

      it 'should disallow access to content if using wrong password' do
        data = g2o_data_header
        sign = sign_data(data, :key => "wrong_password")

        get(data, sign).should respond_with(Net::HTTPForbidden)
      end
    end

    context "using variables to set the data header into the conf" do
      before do
        @uri = URI.parse('http://localhost:8080/using_vars_for_headers/stuff.html')
      end

      it 'should allow access to content with correct G2O headers' do
        data = g2o_data_header
        sign = sign_data(data)
        options = { data_header: 'X-Custom-G2O-Auth-Data', sign_header: 'X-Custom-G2O-Auth-Sign' }

        get(data, sign, options).should respond_with(Net::HTTPOK)
      end

      it 'should disallow access to content if using wrong header' do
        data = g2o_data_header
        sign = sign_data(data)
        options = { data_header: 'X-WRONG-G2O-Auth-Data', sign_header: 'X-WRONG-G2O-Auth-Sign' }

        get(data, sign, options).should respond_with(Net::HTTPForbidden)
      end
    end

    it 'should disallow access to content without G2O headers' do
      get.should respond_with(Net::HTTPForbidden)
    end

    def get(data = nil, sign = nil, options = {})
      Net::HTTP.start(@uri.host, @uri.port) do |http|
        headers = {}
        data_header = options[:data_header] || "X-AKAMAI-G2O-Auth-Data"
        sign_header = options[:sign_header] || "X-AKAMAI-G2O-Auth-Sign"

        headers[data_header] = data if data
        headers[sign_header] = sign if sign

        http.get(@uri.path, headers)
      end
    end

    def sign_data(data, options = {})
      key = (options[:key] or 'a_password')
      digest = OpenSSL::HMAC.digest('md5', key, data + @uri.path)
      Base64.encode64(digest)
    end
  end
end
