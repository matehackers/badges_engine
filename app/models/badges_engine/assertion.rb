require 'uri'
require 'json'
require 'net/http'

module BadgesEngine
  class Assertion < ActiveRecord::Base

    include BadgesEngine::Engine.routes.url_helpers

    attr_accessible :evidence, :expires, :issued_on

    belongs_to :badge

    validates_presence_of :badge_id
    validates_presence_of :user_id

    validates :user_id, :uniqueness => { :scope => :badge_id }

    validates_associated :badge

    # Only one assertion per badge for a given user, makes things easier for us

    before_validation(:on=>:create) do
      self.token = SecureRandom.urlsafe_base64(16)
    end

    class <<self
      def associate_user_class(user_class)
        belongs_to :user, :class_name=>user_class.to_s, :foreign_key=>'user_id'
      end
    end

    def recipient
      'sha256$' + Digest::SHA256.hexdigest(self.user.try(:email) + salt)
    end

    def salt
      BadgesEngine::Configuration.salt
    end

    def baking_callback_url
      origin_uri = URI.parse(BadgesEngine::Configuration.issuer.origin)
      secret_assertion_url(:id=>self.id, :token=>self.token, :host=>origin_uri.host)
    end

    def bake
      uri = URI.parse(BadgesEngine::Configuration.baker_url)
      http = Net::HTTP.new(uri.host, uri.port)
      path = "#{uri.path}?assertion=#{self.baking_callback_url}"
      headers = {'Content-Type'=>'application/json'}
      logger.debug("request: #{uri.host}#{path}")
      response = http.get(path, headers)

      unless response.kind_of?(Net::HTTPSuccess)
        raise "Baking badge failed: Response was not a success:\n\t'#{response.inspect}'"
      end

      if !response || response.body.blank?
        raise "Baking badge failed: Response was blank:\n\t'#{response.inspect}'"
      end

      response.body
    end

    def as_json(options={})
      super(only: [:evidence, :expires, :issued_on], methods: [:recipient, :salt],
            include: { badge: { only: [:version, :name, :image, :description, :criteria], methods: :issuer} })
    end

  end
end
