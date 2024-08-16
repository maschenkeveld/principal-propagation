local openssl_pkey = require "resty.openssl.pkey"
local x509 = require "resty.openssl.x509"
local x509_name = require "resty.openssl.x509.name"
local openssl_digest = require "resty.openssl.digest"
local kong = kong
local redis = require "resty.redis"
local b64 = require "ngx.base64"
local ssl = require "ngx.ssl"

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.1",
}

local function connect_to_redis(plugin_conf)
  local red = redis:new()
  red:set_timeout(1000)
  local ok, err = red:connect(plugin_conf.redis_host, plugin_conf.redis_port)
  if not ok then
    kong.log.err("Failed to connect to Redis: ", err)
    return nil, err
  end

  if plugin_conf.redis_password and plugin_conf.redis_password ~= "" then
    local ok, err = red:auth(plugin_conf.redis_password)
    if not ok then
      kong.log.err("Failed to authenticate with Redis: ", err)
      return nil, err
    end
  end

  return red
end

local function store_in_hash(red, hash_key, field, value)
  local ok, err = red:hset(hash_key, field, value)
  if not ok then
    kong.log.err("Failed to set value in Redis hash: ", err)
    return false, err
  end
  return true
end

local function retrieve_from_hash(red, hash_key, field)
  local res, err = red:hget(hash_key, field)
  if not res then
    kong.log.err("Failed to get value from Redis hash: ", err)
    return nil, err
  end
  if res == ngx.null then
    return nil
  end
  return res
end

local function delete_from_hash(red, hash_key, field)
  local res, err = red:hdel(hash_key, field)
  if not res then
    kong.log.err("Failed to delete field from Redis hash: ", err)
    return false, err
  end
  return true
end

local function set_hash_ttl(red, hash_key, ttl)
  local res, err = red:expire(hash_key, ttl)
  if not res then
    kong.log.err("Failed to set TTL on Redis key: ", err)
    return false
  end
  return true
end

local function retrieve_all_from_hash(red, hash_key)
  local res, err = red:hgetall(hash_key)
  if not res then
    kong.log.err("Failed to get all values from Redis hash: ", err)
    return nil, err
  end
  return res
end

local function store_cert_and_key(red, consumer_id, cert, key, ttl)
  local hash_key = "consumer_local_tls:" .. consumer_id .. ":tls"
  store_in_hash(red, hash_key, "cert", cert)
  store_in_hash(red, hash_key, "key", key)
  set_hash_ttl(red, hash_key, ttl)
end

local function retrieve_cert_and_key(red, consumer_id)
  local hash_key = "consumer_local_tls:" .. consumer_id .. ":tls"
  local cert = retrieve_from_hash(red, hash_key, "cert")
  local key = retrieve_from_hash(red, hash_key, "key")
  return cert, key
end

local function delete_cert_and_key(red, consumer_id)
  local hash_key = "consumer_local_tls:" .. consumer_id .. ":tls"
  delete_from_hash(red, hash_key, "cert")
  delete_from_hash(red, hash_key, "key")
end

function is_cert_expired(cert)
  local x509_cert, err = x509.new(cert, PEM)
  if err then
    kong.log.err("Failed to load certificate: ", err)
    return true
  end

  local now = ngx.time()
  local expiration = x509_cert:get_not_after()

  return now >= expiration
end

function generate_cert_and_key(consumer, ca_chain_pem, ca_key_pem)
  local key, err = openssl_pkey.new({
    type = 'RSA',
    bits = 2048,
    exp = 65537
  })

  if err then
    kong.log.err("Failed to generate private key: ", err)
    return nil, nil
  end

  local cert = x509.new()

  local subject = x509_name.new()
  subject:add("CN", consumer.username or "Kong User")
  cert:set_subject_name(subject)

  local ca_key, err = openssl_pkey.new(ca_key_pem, {
    format = "PEM",
    type = "pr"})
  if err then
    kong.log.err("Failed to load CA private key: ", err)
    return nil, nil
  end

  local ca_chain, err = x509.new(ca_chain_pem)
  if err then
    kong.log.err("Failed to load CA certificate chain: ", err)
    return nil, nil
  end

  local issuer_name = ca_chain:get_subject_name()
  cert:set_issuer_name(issuer_name)

  cert:set_pubkey(key)
  cert:set_not_before(ngx.time())
  cert:set_not_after(ngx.time() + (365 * 24 * 60 * 60))

  local digest = openssl_digest.new("sha256")
  cert:sign(ca_key, digest)

  local fullchain_pem = cert:to_PEM() .. "\n" .. ca_chain:to_PEM()

  return fullchain_pem, key:to_PEM("private")
end

function plugin:access(plugin_conf)

  local consumer = kong.client.get_consumer()
  if not consumer then
    return kong.response.exit(401, "No consumer found")
  end

  local red, err = connect_to_redis(plugin_conf)
  if not red then
    return kong.response.exit(500, { message = "Failed to connect to Redis" })
  end

  local cert, key

  cert, key = retrieve_cert_and_key(red, consumer.id)

  if cert then
    if is_cert_expired(cert) then
      delete_cert_and_key(red, consumer.id)
      cert, key = nil, nil
    end
  end

  if not cert then
    local ca_chain_pem = b64.decode_base64url(plugin_conf.ca_chain_pem_b64)
    local ca_key_pem = b64.decode_base64url(plugin_conf.ca_key_pem_b64)

    cert, key = generate_cert_and_key(consumer, ca_chain_pem, ca_key_pem)
    store_cert_and_key(red, consumer.id, cert, key, plugin_conf.redis_ttl)
  end

  kong.service.set_tls_cert_key(assert(ssl.parse_pem_cert(cert)), assert(ssl.parse_pem_priv_key(key)))
end

return plugin
