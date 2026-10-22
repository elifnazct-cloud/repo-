require 'webrick'
require 'sqlite3'
require 'openssl'
require 'securerandom'
require 'json'
require 'net/smtp'
require 'net/http'
require 'uri'
require 'time'
require 'date'
require 'digest'

ROOT = File.expand_path(__dir__)

def load_env
  path = File.join(ROOT, '.env')
  return unless File.file?(path)
  File.readlines(path, chomp: true).each do |line|
    line = line.strip
    next if line.empty? || line.start_with?('#') || !line.include?('=')
    key, value = line.split('=', 2)
    ENV[key.strip] ||= value.to_s.strip.gsub(/\A["']|["']\z/, '')
  end
end

load_env
HOST = ENV.fetch('HOST', '127.0.0.1')
PORT = ENV.fetch('PORT', '8000').to_i
PUBLIC_URL = ENV.fetch('BEAVIZOR_PUBLIC_URL', ENV.fetch('RENDER_EXTERNAL_URL', "http://127.0.0.1:#{PORT}")).sub(%r{/*$}, '')
DB_PATH = File.expand_path(ENV.fetch('BEAVIZOR_DB', File.join(ROOT, 'beavizor.sqlite3')))
EMAIL_MODE = ENV.fetch('EMAIL_MODE', 'console')
if ENV['RENDER'] == 'true' && ENV.fetch('TEST_ACCESS_PASSWORD', '').length < 20
  abort 'Render test deployment requires TEST_ACCESS_PASSWORD (at least 20 characters).'
end
SESSION_TTL = 14 * 24 * 60 * 60

# sqlite3 2.x accepts bind values as a single array argument.
def db_execute(sql, *binds)
  DB.execute(sql, binds)
end

def db_first_row(sql, *binds)
  DB.get_first_row(sql, binds)
end

DB = SQLite3::Database.new(DB_PATH)
DB.results_as_hash = true
db_execute('PRAGMA foreign_keys = ON')
DB.execute_batch(<<~SQL)
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('customer', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS email_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK(purpose IN ('verify', 'reset')),
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service TEXT NOT NULL,
    price TEXT NOT NULL,
    location TEXT NOT NULL,
    booking_date TEXT NOT NULL,
    booking_time TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'confirmed', 'completed', 'cancelled')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    caption TEXT NOT NULL,
    photo_url TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','published','rejected')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expert_name TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS listings (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('makeup','lashes','nails')),
    description TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    city TEXT NOT NULL,
    photo_url TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','published','rejected')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
SQL

columns = db_execute('PRAGMA table_info(users)').map { |row| row['name'] }
db_execute('ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0') unless columns.include?('email_verified')
admin_email = ENV.fetch('BEAVIZOR_ADMIN_EMAIL', '').strip.downcase
admin_password = ENV.fetch('BEAVIZOR_ADMIN_PASSWORD', '')
if !admin_email.empty? && admin_password.length >= 10
  existing = db_first_row('SELECT id FROM users WHERE email = ?', admin_email)
  if existing
    db_execute("UPDATE users SET role = 'admin', email_verified = 1 WHERE id = ?", existing['id'])
  else
    salt = SecureRandom.random_bytes(16)
    digest = OpenSSL::PKCS5.pbkdf2_hmac(admin_password, salt, 310_000, 32, 'sha256')
    db_execute("INSERT INTO users(name,email,password_hash,email_verified,role) VALUES(?,?,?,1,'admin')",
               'Beavizor Admin', admin_email, "#{salt.unpack1('H*')}:#{digest.unpack1('H*')}")
  end
elsif !admin_email.empty?
  warn 'Admin hesabı oluşturulmadı: BEAVIZOR_ADMIN_PASSWORD en az 10 karakter olmalı.'
end


def json_response(response, status, data)
  response.status = status
  response['Content-Type'] = 'application/json; charset=utf-8'
  response['Cache-Control'] = 'no-store'
  response['X-Content-Type-Options'] = 'nosniff'
  response['Referrer-Policy'] = 'same-origin'
  response.body = JSON.generate(data)
end

def request_data(request)
  raise ArgumentError, 'İstek çok büyük.' if request.body.to_s.bytesize > 65_536
  data = JSON.parse(request.body.to_s.empty? ? '{}' : request.body)
  raise ArgumentError, 'Geçersiz istek.' unless data.is_a?(Hash)
  data
end

def password_hash(password, salt = SecureRandom.random_bytes(16))
  digest = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 310_000, 32, 'sha256')
  "#{salt.unpack1('H*')}:#{digest.unpack1('H*')}"
end

def password_valid?(password, stored)
  salt_hex, digest_hex = stored.split(':', 2)
  return false unless salt_hex && digest_hex
  candidate = password_hash(password, [salt_hex].pack('H*')).split(':', 2)[1]
  return false unless candidate && candidate.bytesize == digest_hex.bytesize
  mismatch = 0
  candidate.bytes.zip(digest_hex.bytes) { |left, right| mismatch |= left ^ right }
  mismatch.zero?
rescue ArgumentError
  false
end

def email_link(recipient, subject, body, url)
  message_text = "#{body}\n#{url}"
  if EMAIL_MODE == 'console'
    puts "DEVELOPMENT EMAIL to=#{recipient} subject=#{subject} link=#{url}"
    return
  elsif EMAIL_MODE == 'resend'
    api_key = ENV.fetch('RESEND_API_KEY', '')
    from = ENV.fetch('RESEND_FROM_EMAIL', '')
    raise 'Resend API anahtarı veya gönderen adresi eksik.' if api_key.empty? || from.empty?
    uri = URI('https://api.resend.com/emails')
    request = Net::HTTP::Post.new(uri)
    request['Authorization'] = "Bearer #{api_key}"
    request['Content-Type'] = 'application/json'
    request['User-Agent'] = 'Beavizor/1.0'
    request.body = JSON.generate({from: from, to: [recipient], subject: subject, text: message_text})
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 10, read_timeout: 15) do |http|
      http.request(request)
    end
    unless response.is_a?(Net::HTTPSuccess)
      warn "Resend email delivery rejected: HTTP #{response.code}"
      raise 'E-posta gönderimi başarısız.'
    end
    return
  elsif EMAIL_MODE != 'smtp'
    raise 'EMAIL_MODE değeri console, smtp veya resend olmalı.'
  end

  host = ENV.fetch('SMTP_HOST', '')
  raise 'SMTP_HOST ayarı eksik.' if host.empty?
  port = ENV.fetch('SMTP_PORT', '587').to_i
  from = ENV.fetch('SMTP_FROM', ENV.fetch('SMTP_USER', ''))
  user = ENV.fetch('SMTP_USER', '')
  password = ENV.fetch('SMTP_PASSWORD', '')
  message = "From: #{from}\r\nTo: #{recipient}\r\nSubject: #{subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n#{body}\r\n#{url}\r\n"
  smtp = Net::SMTP.new(host, port)
  smtp.enable_starttls if ENV.fetch('SMTP_SECURITY', 'starttls') == 'starttls'
  smtp.start(ENV.fetch('SMTP_HELO', 'localhost'), user, password, user.empty? ? :none : :login) { |connection| connection.send_message(message, from, recipient) }
end

def issue_token(user_id, purpose)
  token = SecureRandom.urlsafe_base64(32)
  db_execute('DELETE FROM email_tokens WHERE user_id = ? AND purpose = ?', user_id, purpose)
  db_execute('INSERT INTO email_tokens(token_hash,user_id,purpose,expires_at) VALUES(?,?,?,?)',
             Digest::SHA256.hexdigest(token), user_id, purpose, Time.now.to_i + 3600)
  token
end

require 'digest'

server = WEBrick::HTTPServer.new(BindAddress: HOST, Port: PORT, MaxClients: 1, AccessLog: [], Logger: WEBrick::Log.new($stdout, WEBrick::Log::WARN))
server.mount_proc('/') do |request, response|
  path = request.path
  response['Cache-Control'] = 'no-store'
  response['X-Content-Type-Options'] = 'nosniff'
  response['Referrer-Policy'] = 'no-referrer'
  response['X-Frame-Options'] = 'DENY'
  response['X-Robots-Tag'] = 'noindex, nofollow'
  if request.request_method == 'GET' && path == '/healthz'
    json_response(response, 200, { ok: true })
    next
  end
  unless ENV.fetch('TEST_ACCESS_PASSWORD', '').empty?
    WEBrick::HTTPAuth.basic_auth(request, response, 'Beavizor Test') do |username, password|
      expected = Digest::SHA256.hexdigest(ENV.fetch('TEST_ACCESS_PASSWORD'))
      actual = Digest::SHA256.hexdigest(password.to_s)
      username == 'beavizor' && OpenSSL.fixed_length_secure_compare(expected, actual)
    end
  end
  if request.request_method == 'POST' && request['origin'] && request['origin'] != PUBLIC_URL
    json_response(response, 403, { error: 'Geçersiz istek kaynağı.' })
    next
  end
  if request.request_method == 'GET' && ['/','/iphone-empty-screen.html'].include?(path)
    response.status = 200
    response['Content-Type'] = 'text/html; charset=utf-8'
    response.body = File.binread(File.join(ROOT, 'iphone-empty-screen.html'))
    next
  end
  if request.request_method == 'GET' && path.match?(%r{\A/(makeup-[\w-]+|lashes-sample|nails-sample)\.svg\z})
    asset = File.join(ROOT, path.delete_prefix('/'))
    if File.file?(asset)
      response.status = 200
      response['Content-Type'] = 'image/svg+xml'
      response.body = File.binread(asset)
      next
    end
  end

  begin
    if request.request_method == 'GET' && path == '/api/me'
      token = request.cookies.find { |cookie| cookie.name == 'beavizor_session' }&.value
      user = token && db_first_row('SELECT users.id,users.name,users.email,users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?', Digest::SHA256.hexdigest(token), Time.now.to_i)
      json_response(response, 200, user ? { user: user } : { user: nil })
    elsif request.request_method == 'GET' && path.start_with?('/api/')
      user = current_user(request)
      if path == '/api/bookings' || path == '/api/messages' || path == '/api/my-listings' || path == '/api/my-posts'
        unless user
          json_response(response, 401, { error: 'Oturum açmanız gerekiyor.' })
          next
        end
        if path == '/api/bookings'
          rows = db_execute('SELECT * FROM bookings WHERE user_id=? ORDER BY id DESC', user['id'])
          json_response(response, 200, { bookings: rows })
        elsif path == '/api/messages'
          rows = db_execute('SELECT id,expert_name,body,created_at FROM messages WHERE user_id=? ORDER BY id ASC', user['id'])
          json_response(response, 200, { messages: rows })
        elsif path == '/api/my-posts'
          rows = db_execute('SELECT id,caption,photo_url,status,created_at FROM posts WHERE user_id=? ORDER BY id DESC LIMIT 50',user['id'])
          json_response(response,200,{posts:rows})
        else
          rows = db_execute('SELECT * FROM listings WHERE user_id=? ORDER BY id DESC', user['id'])
          json_response(response, 200, { listings: rows })
        end
      elsif path == '/api/admin/overview'
        unless user && user['role'] == 'admin'
          json_response(response, user ? 403 : 401, { error: user ? 'Yönetici erişimi gerekli.' : 'Oturum açmanız gerekiyor.' })
          next
        end
        users = db_execute('SELECT id,name,email,role,created_at FROM users ORDER BY id DESC')
        bookings = db_execute('SELECT bookings.*,users.name AS customer_name,users.email AS customer_email FROM bookings JOIN users ON users.id=bookings.user_id ORDER BY bookings.id DESC')
        listings = db_execute('SELECT listings.*,users.name AS seller_name,users.email AS seller_email FROM listings JOIN users ON users.id=listings.user_id ORDER BY listings.id DESC')
        posts = db_execute('SELECT posts.*, users.name AS author_name FROM posts JOIN users ON users.id=posts.user_id ORDER BY posts.id DESC LIMIT 100')
        json_response(response, 200, { users: users, bookings: bookings, listings: listings, posts: posts })
      elsif path == '/api/posts'
        rows = db_execute("SELECT posts.id,posts.caption,posts.photo_url,posts.created_at,users.name AS author_name FROM posts JOIN users ON users.id=posts.user_id WHERE posts.status='published' ORDER BY posts.id DESC LIMIT 50")
        json_response(response,200,{posts:rows})
      elsif path == '/api/listings'
        rows = db_execute("SELECT listings.*,users.name AS seller_name FROM listings JOIN users ON users.id=listings.user_id WHERE listings.status='published' AND users.email_verified=1 ORDER BY listings.id DESC")
        json_response(response, 200, { listings: rows })
      else
        json_response(response, 404, { error: 'Bulunamadı.' })
      end
    elsif request.request_method == 'POST'
      data = request_data(request)
      if ['/api/register','/api/login'].include?(path)
        email = data.fetch('email', '').to_s.strip.downcase
        password = data.fetch('password', '').to_s
        name = data.fetch('name', '').to_s.strip
        raise ArgumentError, 'Geçerli e-posta ve şifre gerekli.' if email.length > 254 || !email.include?('@') || password.empty? || password.length > 200
        if path == '/api/register'
          raise ArgumentError, 'Ad en az 2 karakter olmalı.' if name.length < 2 || name.length > 80
          raise ArgumentError, 'Kayıt şifresi en az 10 karakter olmalı.' if password.length < 10
          begin
            db_execute('INSERT INTO users(name,email,password_hash,email_verified) VALUES(?,?,?,1)', name,email,password_hash(password))
          rescue SQLite3::ConstraintException
            json_response(response,409,{error:'Bu e-posta adresi zaten kayıtlı. Giriş yapmayı deneyin.'})
            next
          end
          user_id = DB.last_insert_row_id
          token = SecureRandom.urlsafe_base64(32)
          db_execute('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)',Digest::SHA256.hexdigest(token),user_id,Time.now.to_i+SESSION_TTL)
          secure_attribute = PUBLIC_URL.start_with?('https://') ? '; Secure' : ''
          response['Set-Cookie'] = "beavizor_session=#{token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=#{SESSION_TTL}#{secure_attribute}"
          json_response(response,201,{user:{id:user_id,name:name,email:email,role:'customer'}})
        else
          user = db_first_row('SELECT id,name,email,role,email_verified,password_hash FROM users WHERE email=?',email)
          unless user && password_valid?(password,user['password_hash'])
            json_response(response,401,{error:'E-posta veya şifre hatalı.'})
            next
          end
          # Successful password login is sufficient; mark legacy pending accounts as active.
          if user['email_verified'].to_i != 1
            db_execute('UPDATE users SET email_verified=1 WHERE id=?',user['id'])
            user['email_verified'] = 1
          end
          token = SecureRandom.urlsafe_base64(32)
          db_execute('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)',Digest::SHA256.hexdigest(token),user['id'],Time.now.to_i+SESSION_TTL)
          secure_attribute = PUBLIC_URL.start_with?('https://') ? '; Secure' : ''
          response['Set-Cookie'] = "beavizor_session=#{token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=#{SESSION_TTL}#{secure_attribute}"
          user.delete('password_hash')
          json_response(response,200,{user:user})
        end
      elsif path == '/api/verify-email'
        token = data.fetch('token','').to_s
        row = db_first_row("SELECT user_id FROM email_tokens WHERE token_hash=? AND purpose='verify' AND expires_at>?",Digest::SHA256.hexdigest(token),Time.now.to_i)
        unless row
          json_response(response,400,{error:'Doğrulama bağlantısı geçersiz veya süresi dolmuş.'})
          next
        end
        db_execute('UPDATE users SET email_verified=1 WHERE id=?',row['user_id'])
        db_execute('DELETE FROM email_tokens WHERE token_hash=?',Digest::SHA256.hexdigest(token))
        json_response(response,200,{ok:true,message:'E-posta adresin doğrulandı. Şimdi giriş yapabilirsin.'})
      elsif path == '/api/forgot-password'
        email = data.fetch('email','').to_s.strip.downcase
        user = db_first_row('SELECT id,name FROM users WHERE email=? AND email_verified=1',email)
        if user
          token = issue_token(user['id'],'reset')
          link = "#{PUBLIC_URL}/?reset=#{URI.encode_www_form_component(token)}"
          email_link(email,'Beavizor şifre yenileme','Şifreni yenilemek için bağlantıyı aç:',link)
        end
        json_response(response,200,{ok:true,message:'Adres kayıtlıysa şifre yenileme bağlantısı e-posta ile gönderildi.'})
      elsif path == '/api/reset-password'
        token = data.fetch('token','').to_s
        password = data.fetch('password','').to_s
        raise ArgumentError,'Şifre en az 10 karakter olmalı.' if password.length < 10 || password.length > 200
        digest = Digest::SHA256.hexdigest(token)
        row = db_first_row("SELECT user_id FROM email_tokens WHERE token_hash=? AND purpose='reset' AND expires_at>?",digest,Time.now.to_i)
        unless row
          json_response(response,400,{error:'Şifre yenileme bağlantısı geçersiz veya süresi dolmuş.'})
          next
        end
        db_execute('UPDATE users SET password_hash=? WHERE id=?',password_hash(password),row['user_id'])
        db_execute("DELETE FROM email_tokens WHERE user_id=? AND purpose='reset'",row['user_id'])
        db_execute('DELETE FROM sessions WHERE user_id=?',row['user_id'])
        json_response(response,200,{ok:true,message:'Şifren güncellendi. Yeni şifrenle giriş yapabilirsin.'})
      elsif path == '/api/logout'
        token = request.cookies.find { |cookie| cookie.name == 'beavizor_session' }&.value
        db_execute('DELETE FROM sessions WHERE token_hash=?',Digest::SHA256.hexdigest(token)) if token
        response['Set-Cookie'] = 'beavizor_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
        json_response(response,200,{ok:true})
      elsif path == '/api/bookings'
        user = current_user(request)
        unless user
          json_response(response,401,{error:'Oturum açmanız gerekiyor.'})
          next
        end
        service=data.fetch('service','').to_s.strip[0,100]
        price=data.fetch('price','').to_s.strip[0,20]
        address=data.fetch('location','').to_s.strip[0,500]
        date=data.fetch('date','').to_s
        time=data.fetch('time','').to_s
        parsed=Date.strptime(date,'%Y-%m-%d') rescue nil
        raise ArgumentError,'Randevu tarihi geçersiz. Yarın ile 60 gün sonrasını seçin.' unless parsed && parsed.strftime('%Y-%m-%d') == date && parsed > Date.today && parsed <= Date.today + 60
        raise ArgumentError,'Hizmet, adres ve geçerli saat gerekli.' if service.empty? || price.empty? || address.length < 5 || !%w[10:00 13:30 16:00 18:30].include?(time)
        conflict=db_first_row("SELECT id FROM bookings WHERE user_id=? AND booking_date=? AND booking_time=? AND status IN ('pending','confirmed') LIMIT 1",user['id'],date,time)
        if conflict
          json_response(response,409,{error:'Bu saatte zaten aktif bir randevu talebiniz var.'})
          next
        end
        db_execute('INSERT INTO bookings(user_id,service,price,location,booking_date,booking_time) VALUES(?,?,?,?,?,?)',user['id'],service,price,address,date,time)
        booking=db_first_row('SELECT * FROM bookings WHERE id=?',DB.last_insert_row_id)
        json_response(response,201,{booking:booking})
      elsif path =~ %r{\A/api/bookings/(\d+)/cancel\z}
        user=current_user(request)
        unless user
          json_response(response,401,{error:'Oturum açmanız gerekiyor.'})
          next
        end
        booking_id=path[%r{/api/bookings/(\d+)/cancel},1].to_i
        booking=db_first_row('SELECT id,status,booking_date FROM bookings WHERE id=? AND user_id=?',booking_id,user['id'])
        unless booking
          json_response(response,404,{error:'Randevu bulunamadı.'})
          next
        end
        unless %w[pending confirmed].include?(booking['status']) && booking['booking_date'] >= Date.today.iso8601
          json_response(response,409,{error:'Bu randevu artık iptal edilemiyor.'})
          next
        end
        db_execute("UPDATE bookings SET status='cancelled' WHERE id=? AND user_id=?",booking_id,user['id'])
        json_response(response,200,{ok:true,message:'Randevu talebiniz iptal edildi.'})
      elsif path == '/api/posts'
        user=current_user(request)
        unless user
          json_response(response,401,{error:'Gönderi paylaşmak için giriş yapın.'})
          next
        end
        caption=data.fetch('caption','').to_s.strip
        photo_url=data.fetch('photo_url','').to_s.strip
        raise ArgumentError,'Gönderi açıklaması 5-1000 karakter olmalı.' unless caption.length.between?(5,1000)
        raise ArgumentError,'Fotoğraf için geçerli bir HTTPS bağlantısı gerekli.' unless photo_url.empty? || (photo_url.length <= 500 && photo_url.match?(%r{\Ahttps://[^\s]+\z}))
        db_execute("INSERT INTO posts(user_id,caption,photo_url,status) VALUES(?,?,?,'pending')",user['id'],caption,photo_url)
        post=db_first_row('SELECT id,caption,photo_url,status,created_at FROM posts WHERE id=?',DB.last_insert_row_id)
        json_response(response,201,{post:post,message:'Gönderin paylaşıldı; yönetici onayı bekliyor.'})
      elsif path == '/api/listings'
        user = current_user(request)
        unless user
          json_response(response, 401, { error: 'İlan açmak için giriş yapmanız gerekiyor.' })
          next
        end
        title = data.fetch('title', '').to_s.strip
        category = data.fetch('category', '').to_s
        description = data.fetch('description', '').to_s.strip
        city = data.fetch('city', '').to_s.strip
        price = data.fetch('price', '').to_s
        photo_url = data.fetch('photo_url', '').to_s.strip
        raise ArgumentError, 'İlan başlığı 4-80 karakter olmalı.' unless title.length.between?(4, 80)
        raise ArgumentError, 'Hizmet türü seçin.' unless %w[makeup lashes nails].include?(category)
        raise ArgumentError, 'Açıklama 20-1500 karakter olmalı.' unless description.length.between?(20, 1500)
        raise ArgumentError, 'Şehir 2-60 karakter olmalı.' unless city.length.between?(2, 60)
        raise ArgumentError, 'Fiyat 100-100000 TL arasında olmalı.' unless price.match?(/\A\d{1,6}\z/) && price.to_i.between?(100, 100_000)
        raise ArgumentError, 'Fotoğraf bağlantısı HTTPS olmalı.' unless photo_url.empty? || photo_url.match?(%r{\Ahttps://[^\s]{1,500}\z})
        db_execute("INSERT INTO listings(user_id,title,category,description,price_cents,city,photo_url,status) VALUES(?,?,?,?,?,?,?,'pending')",
                   user['id'], title, category, description, price.to_i * 100, city, photo_url)
        listing = db_first_row('SELECT * FROM listings WHERE id=?', DB.last_insert_row_id)
        json_response(response, 201, { listing: listing, message: 'İlanın yönetici onayına gönderildi.' })
      elsif path == '/api/messages'
        user=current_user(request)
        unless user
          json_response(response,401,{error:'Oturum açmanız gerekiyor.'})
          next
        end
        expert=data.fetch('expert_name','').to_s.strip[0,100]
        body=data.fetch('body','').to_s.strip
        raise ArgumentError,'Uzman ve 1-2000 karakter arası mesaj gerekli.' if expert.empty? || body.empty? || body.length>2000
        db_execute('INSERT INTO messages(user_id,expert_name,body) VALUES(?,?,?)',user['id'],expert,body)
        row=db_first_row('SELECT id,expert_name,body,created_at FROM messages WHERE id=?',DB.last_insert_row_id)
        json_response(response,201,{message:row})
      elsif path =~ %r{\A/api/admin/listings/(\d+)/status\z}
        user = current_user(request)
        unless user && user['role'] == 'admin'
          json_response(response, user ? 403 : 401, { error: user ? 'Yönetici erişimi gerekli.' : 'Oturum açmanız gerekiyor.' })
          next
        end
        listing_id = path[%r{/api/admin/listings/(\d+)/status}, 1].to_i
        status = data.fetch('status', '').to_s
        raise ArgumentError, 'İlan durumu geçersiz.' unless %w[published rejected].include?(status)
        db_execute('UPDATE listings SET status=? WHERE id=?', status, listing_id)
        json_response(response, 200, { ok: true })
      elsif path =~ %r{\A/api/admin/posts/(\d+)/status\z}
        user=current_user(request)
        unless user && user['role']=='admin'
          json_response(response,user ? 403 : 401,{error:'Yönetici erişimi gerekli.'})
          next
        end
        post_id=path[%r{/api/admin/posts/(\d+)/status},1].to_i
        status=data.fetch('status','').to_s
        raise ArgumentError,'Gönderi durumu geçersiz.' unless %w[published rejected].include?(status)
        db_execute('UPDATE posts SET status=? WHERE id=?',status,post_id)
        json_response(response,200,{ok:true})
      elsif path =~ %r{\A/api/admin/bookings/(\d+)/status\z}
        user = current_user(request)
        unless user && user['role'] == 'admin'
          json_response(response, user ? 403 : 401, { error: user ? 'Yönetici erişimi gerekli.' : 'Oturum açmanız gerekiyor.' })
          next
        end
        booking_id = path[%r{/api/admin/bookings/(\d+)/status}, 1].to_i
        status = data.fetch('status', '').to_s
        raise ArgumentError, 'Durum geçersiz.' unless %w[pending confirmed completed cancelled].include?(status)
        db_execute('UPDATE bookings SET status=? WHERE id=?', status, booking_id)
        json_response(response, 200, { ok: true })
      else
        json_response(response,404,{error:'Bulunamadı.'})
      end
    else
      json_response(response,405,{error:'Yöntem desteklenmiyor.'})
    end
  rescue ArgumentError, JSON::ParserError => error
    json_response(response,400,{error:error.message})
  rescue StandardError => error
    warn "İstek hatası: #{error.class}: #{error.message}"
    json_response(response,500,{error:'Sunucuda beklenmeyen bir hata oluştu.'})
  end
end


def current_user(request)
  token = request.cookies.find { |cookie| cookie.name == 'beavizor_session' }&.value
  return nil unless token
  row=db_first_row('SELECT users.id,users.name,users.email,users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?',Digest::SHA256.hexdigest(token),Time.now.to_i)
  row
end

trap('INT') { server.shutdown }
trap('TERM') { server.shutdown }
puts "Beavizor çalışıyor: http://#{HOST}:#{PORT}"
server.start
