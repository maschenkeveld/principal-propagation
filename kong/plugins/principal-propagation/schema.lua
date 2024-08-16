local typedefs = require "kong.db.schema.typedefs"

local PLUGIN_NAME = "principal-propagation"

local schema = {
  name = PLUGIN_NAME,
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { redis_ttl = {
              type = "integer",
              default = 600,
              required = true,
              gt = 0, }},
          { redis_host = {
              type = "string",
              required = true,
              default = "my-redis-host.com" } },
          { redis_port = {
              type = "integer",
              required = true,
              default = 6379 } },
          { redis_username = {
              type = "string",
              required = false } },
          { redis_password = {
              type = "string",
              required = false } },
          { ca_cert_pem_b64 = {
              type = "string",
              required = true } },
          { ca_key_pem_b64 = {
              type = "string",
              required = true } },
        },
        entity_checks = {

        },
      },
    },
  },
}

return schema