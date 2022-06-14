local _M = {}
local _MT = { __index = _M, }

local schema = require("resty.router.schema")
local router = require("resty.router.router")
local context = require("resty.router.context")
local constants = require("kong.constants")
local bit = require("bit")
local ffi = require("ffi")


local tb_clear = require("table.clear")
local re_find = ngx.re.find
local re_match = ngx.re.match
local get_method = ngx.req.get_method
local server_name = require("ngx.ssl").server_name
local normalize = require("kong.tools.uri").normalize
local hostname_type = require("kong.tools.utils").hostname_type
local find = string.find
local lower = string.lower
local byte = string.byte
local sub = string.sub
local ffi_new = ffi.new
local max = math.max
local split_port = require("kong.router.traditional").split_port
local bor, band, lshift, rshift = bit.bor, bit.band, bit.lshift, bit.rshift
local tb_size = require("pl.tablex").size
local header        = ngx.header
local var           = ngx.var
local ngx_log       = ngx.log
local ERR           = ngx.ERR
local get_method    = ngx.req.get_method
local get_headers   = ngx.req.get_headers
local is_http = ngx.config.subsystem == "http"



local SLASH         = byte("/")


function _M._set_ngx(mock_ngx)
  if type(mock_ngx) ~= "table" then
    return
  end

  if mock_ngx.header then
    header = mock_ngx.header
  end

  if mock_ngx.var then
    var = mock_ngx.var
  end

  if mock_ngx.log then
    ngx_log = mock_ngx.log
  end

  if mock_ngx.ERR then
    ERR = mock_ngx.ERR
  end

  if type(mock_ngx.req) == "table" then
    if mock_ngx.req.get_method then
      get_method = mock_ngx.req.get_method
    end

    if mock_ngx.req.get_headers then
      get_headers = mock_ngx.req.get_headers
    end
  end

  if type(mock_ngx.config) == "table" then
    if mock_ngx.config.subsystem then
      is_http = mock_ngx.config.subsystem == "http"
    end
  end

  if type(mock_ngx.re) == "table" then
    if mock_ngx.re.match then
      re_match = mock_ngx.re.match
    end

    if mock_ngx.re.find then
      re_find = mock_ngx.re.find
    end
  end
end


local protocol_subsystem = constants.PROTOCOLS_WITH_SUBSYSTEM


local normalize_regex
do
  local RESERVED_CHARACTERS = {
    [0x21] = true, -- !
    [0x23] = true, -- #
    [0x24] = true, -- $
    [0x25] = true, -- %
    [0x26] = true, -- &
    [0x27] = true, -- '
    [0x28] = true, -- (
    [0x29] = true, -- )
    [0x2A] = true, -- *
    [0x2B] = true, -- +
    [0x2C] = true, -- ,
    [0x2F] = true, -- /
    [0x3A] = true, -- :
    [0x3B] = true, -- ;
    [0x3D] = true, -- =
    [0x3F] = true, -- ?
    [0x40] = true, -- @
    [0x5B] = true, -- [
    [0x5D] = true, -- ]
  }
  local REGEX_META_CHARACTERS = {
    [0x2E] = true, -- .
    [0x5E] = true, -- ^
    -- $ in RESERVED_CHARACTERS
    -- * in RESERVED_CHARACTERS
    -- + in RESERVED_CHARACTERS
    [0x2D] = true, -- -
    -- ? in RESERVED_CHARACTERS
    -- ( in RESERVED_CHARACTERS
    -- ) in RESERVED_CHARACTERS
    -- [ in RESERVED_CHARACTERS
    -- ] in RESERVED_CHARACTERS
    [0x7B] = true, -- {
    [0x7D] = true, -- }
    [0x5C] = true, -- \
    [0x7C] = true, -- |
  }
  local ngx_re_gsub = ngx.re.gsub
  local string_char = string.char

  local function percent_decode(m)
    local hex = m[1]
    local num = tonumber(hex, 16)
    if RESERVED_CHARACTERS[num] then
      return upper(m[0])
    end

    local chr = string_char(num)
    if REGEX_META_CHARACTERS[num] then
      return "\\" .. chr
    end

    return chr
  end

  function normalize_regex(regex)
    if find(regex, "%", 1, true) then
      -- Decoding percent-encoded triplets of unreserved characters
      return ngx_re_gsub(regex, "%([\\dA-F]{2})", percent_decode, "joi")
    end
    return regex
  end
end


local function gen_for_field(name, op, vals, vals_transform)
  local values_n = 0
  local values = {}

  if vals then
    for _, p in ipairs(vals) do
      values_n = values_n + 1
      local op = (type(op) == "string") and op or op(p)
      values[values_n] = name .. " " .. op ..
                         " \"" .. (vals_transform and vals_transform(op, p) or p) .. "\""
    end

    if values_n > 0 then
      return "(" .. table.concat(values, " || ") .. ")"
    end
  end

  return nil
end


local function get_atc(route)
  local out = {}
  local out_n = 0

  local gen = gen_for_field("net.protocol", "==", route.protocols)
  if gen then
    table.insert(out, gen)
  end

  local gen = gen_for_field("http.method", "==", route.methods)
  if gen then
    table.insert(out, gen)
  end

  local gen = gen_for_field("tls.sni", "==", route.snis)
  if gen then
    table.insert(out, gen)
  end

  local gen = gen_for_field("http.host", function(host)
    if host:sub(1, 1) == "*" then
      -- postfix matching
      return "=^"
    end

    if host:sub(-1) == "*" then
      -- prefix matching
      return "^="
    end

    return "=="
  end, route.hosts, function(op, p)
    if op == "=^" then
      return p:sub(2)
    end

    if op == "^=" then
      return p:sub(1, -2)
    end

    return p
  end)
  if gen then
    table.insert(out, gen)
  end

  local gen = gen_for_field("http.path", function(path)
    return re_find(path, [[[a-zA-Z0-9\.\-_~/%]*$]], "ajo") and "^=" or "~"
  end, route.paths, function(op, p)
    if op == "~" then
      return normalize_regex(p):gsub("\\", "\\\\")
    end

    return normalize(p, true)
  end)
  if gen then
    table.insert(out, gen)
  end

  if route.headers then
    local headers = {}
    for h, v in pairs(route.headers) do
      local single_header = {}
      for _, ind in ipairs(v) do
        local name = "http.headers." .. h:gsub("-", "_"):lower()
        local value = ind
        local op = "=="
        if ind:sub(1, 2) == "~*" then
          value = ind:sub(3):gsub("\\", "\\\\")
          op = "~"
        end

        table.insert(single_header, name .. " " .. op .. " \"" .. value:lower() .. "\"")
      end

      table.insert(headers, "(" .. table.concat(single_header, " || ") .. ")")
    end

    table.insert(out, table.concat(headers, " && "))
  end

  return table.concat(out, " && ")
end


-- convert a route to a priority value for use in the ATC router
-- priority must be a 64-bit non negative integer
-- format (big endian):
--  0                   1                   2                   3
--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- +-----+-+---------------+-+-------------------------------------+
-- | W   |P| Header        |R|  Regex                              |
-- | G   |L|               |G|  Priority                           |
-- | T   |N| Count         |X|                                     |
-- +-----+-+-----------------+-------------------------------------+
-- |  Regex Priority         |   Max Length                        |
-- |  (cont)                 |                                     |
-- |                         |                                     |
-- +-------------------------+-------------------------------------+
local function route_priority(r)
  local match_weight = 0

  if r.methods and #r.methods > 0 then
    match_weight = match_weight + 1
  end

  if r.hosts and #r.hosts > 0 then
    match_weight = match_weight + 1
  end

  if r.paths and #r.paths > 0 then
    match_weight = match_weight + 1
  end

  local headers_count = r.headers and tb_size(r.headers) or 0

  if headers_count > 0 then
    match_weight = match_weight + 1
  end

  if headers_count > 255 then
    ngx_log(ngx_WARN, "too many headers in route ", r.id,
                      " headers count capped at 255 when sorting")
    headers_count = 255
  end

  if r.snis and #r.snis > 0 then
    match_weight = match_weight + 1
  end

  local plain_host_only = not not r.hosts

  if r.hosts then
    for _, h in ipairs(r.hosts) do
      if h:find("*", nil, true) then
        plain_host_only = false
        break
      end
    end
  end

  local max_uri_length = 0
  local regex_url = false

  if r.paths then
    for _, p in ipairs(r.paths) do
      if re_find(p, [[[a-zA-Z0-9\.\-_~/%]*$]], "ajo") then
        -- plain URI or URI prefix
        max_uri_length = max(max_uri_length, #p)

      else
        regex_url = true
      end
    end
  end

  match_weight = lshift(ffi_new("uint64_t", match_weight), 61)
  headers_count = lshift(ffi_new("uint64_t", headers_count), 52)
  local regex_priority = lshift(ffi_new("uint64_t", regex_url and r.regex_priority or 0), 19)
  local max_length = band(max_uri_length, 0x7FFFF)

  local priority =  bor(match_weight,
                        plain_host_only and lshift(0x01ULL, 60) or 0,
                        regex_url and lshift(0x01ULL, 51) or 0,
                        headers_count,
                        regex_priority,
                        max_length)

  return priority
end


function _M.new(routes)
  if type(routes) ~= "table" then
    return error("expected arg #1 routes to be a table")
  end

  local s = schema.new()
  s:add_field("net.protocol", "String")
  s:add_field("tls.sni", "String")
  s:add_field("http.method", "String")
  s:add_field("http.host", "String")
  s:add_field("http.path", "String")
  s:add_field("http.raw_path", "String")
  s:add_field("http.headers.*", "String")

  local inst = router.new(s)

  local router = setmetatable({
    schema = s,
    router = inst,
    routes = {},
    services = {},
    fields = {},
  }, _MT)

  for _, r in ipairs(routes) do
    router.routes[r.route.id] = r.route
    router.services[r.route.id] = r.service

    print(get_atc(r.route))
    assert(inst:add_matcher(route_priority(r.route), r.route.id, get_atc(r.route)))

    router.fields = inst:get_fields()
  end

  return router
end


local function sanitize_uri_postfix(uri_postfix)
  if not uri_postfix or uri_postfix == "" then
    return uri_postfix
  end

  if uri_postfix == "." or uri_postfix == ".." then
    return ""
  end

  if sub(uri_postfix, 1, 2) == "./" then
    return sub(uri_postfix, 3)
  end

  if sub(uri_postfix, 1, 3) == "../" then
    return sub(uri_postfix, 4)
  end

  return uri_postfix
end


function _M:select(req_method, req_uri, req_host, req_scheme,
                   _src_ip, _src_port,
                   _dst_ip, _dst_port,
                   sni, req_headers)
  if req_method and type(req_method) ~= "string" then
    error("method must be a string", 2)
  end
  if req_uri and type(req_uri) ~= "string" then
    error("uri must be a string", 2)
  end
  if req_host and type(req_host) ~= "string" then
    error("host must be a string", 2)
  end
  if req_scheme and type(req_scheme) ~= "string" then
    error("scheme must be a string", 2)
  end
  if src_ip and type(src_ip) ~= "string" then
    error("src_ip must be a string", 2)
  end
  if src_port and type(src_port) ~= "number" then
    error("src_port must be a number", 2)
  end
  if dst_ip and type(dst_ip) ~= "string" then
    error("dst_ip must be a string", 2)
  end
  if dst_port and type(dst_port) ~= "number" then
    error("dst_port must be a number", 2)
  end
  if sni and type(sni) ~= "string" then
    error("sni must be a string", 2)
  end
  if req_headers and type(req_headers) ~= "table" then
    error("headers must be a table", 2)
  end

  local c = context.new(self.schema)

  for _, field in ipairs(self.fields) do
    if field == "http.method" then
      assert(c:add_value("http.method", req_method))

    elseif field == "http.path" then
      assert(c:add_value("http.path", req_uri))

    elseif field == "http.host" then
      assert(c:add_value("http.host", req_host))

    elseif field == "net.protocol" then
      assert(c:add_value("net.protocol", req_scheme))

    elseif field == "tls.sni" then
      assert(c:add_value("tls.sni", sni))

    elseif req_headers and field:sub(1, 13) == "http.headers." then
      local h = field:sub(14)
      local v = req_headers[h]

      if v then
        if type(v) == "string" then
          assert(c:add_value(field, v:lower()))

        else
          -- TODO: support array of values
          assert(c:add_value(field, v[1]:lower()))
        end
      end
    end
  end

  local matched = self.router:execute(c)
  if not matched then
    return nil
  end

  local uuid, matched_path, captures = c:get_result()

  local service_protocol
  local service_type
  local service_host
  local service_port
  local service = self.services[uuid]
  local matched_route = self.routes[uuid]

  if service then
    service_protocol = service.protocol
    service_host = service.host
    service_port = service.port
  end

  if service_protocol then
    service_type = protocol_subsystem[service_protocol]
  end

  local service_hostname_type
  if service_host then
    service_hostname_type = hostname_type(service_host)
  end

  if not service_port then
    if service_protocol == "https" then
      service_port = 443
    elseif service_protocol == "http" then
      service_port = 80
    end
  end

  local service_path
  if service_type == "http" then
    service_path = service and service.path or "/"
  end

  local request_prefix = matched_route.strip_path and matched_path or nil
  local upstream_uri
  local request_postfix = request_prefix and req_uri:sub(#matched_path + 1) or req_uri:sub(2, -1)
  request_postfix = sanitize_uri_postfix(request_postfix) or ""
  local upstream_base = service_path or "/"

  if byte(upstream_base, -1) == SLASH then
    -- ends with / and strip_path = true
    if matched_route.strip_path then
      if request_postfix == "" then
        if upstream_base == "/" then
          upstream_uri = "/"
        elseif byte(req_uri, -1) == SLASH then
          upstream_uri = upstream_base
        else
          upstream_uri = sub(upstream_base, 1, -2)
        end
      elseif byte(request_postfix, 1, 1) == SLASH then
        -- double "/", so drop the first
        upstream_uri = sub(upstream_base, 1, -2) .. request_postfix
      else -- ends with / and strip_path = true, no double slash
        upstream_uri = upstream_base .. request_postfix
      end

    else -- ends with / and strip_path = false
      -- we retain the incoming path, just prefix it with the upstream
      -- path, but skip the initial slash
      upstream_uri = upstream_base .. sub(req_uri, 2)
    end

  else -- does not end with /
    -- does not end with / and strip_path = true
    if matched_route.strip_path then
      if request_postfix == "" then
        if #req_uri > 1 and byte(req_uri, -1) == SLASH then
          upstream_uri = upstream_base .. "/"
        else
          upstream_uri = upstream_base
        end
      elseif byte(request_postfix, 1, 1) == SLASH then
        upstream_uri = upstream_base .. request_postfix
      else
        upstream_uri = upstream_base .. "/" .. request_postfix
      end

    else -- does not end with / and strip_path = false
      if req_uri == "/" then
        upstream_uri = upstream_base
      else
        upstream_uri = upstream_base .. req_uri
      end
    end
  end

  return {
    route           = matched_route,
    service         = service,
    prefix          = request_prefix,
    matches = {
      uri_captures = (captures and captures[1]) and captures or nil,
    },
    upstream_url_t = {
      type = service_protocol,
      host = service_host,
      port = service_port,
    },
    upstream_scheme = service_protocol,
    upstream_uri    = upstream_uri,
    upstream_host   = matched_route.preserve_host and req_host or nil,
  }
end


function _M:exec(ctx)
  local req_method = get_method()
  local req_uri = ctx and ctx.request_uri or var.request_uri
  local req_host = var.http_host
  local req_scheme = ctx and ctx.scheme or var.scheme
  local sni = server_name()

  local headers, err = get_headers(MAX_REQ_HEADERS)
  if err == "truncated" then
    log(WARN, "retrieved ", MAX_REQ_HEADERS, " headers for evaluation ",
              "(max) but request had more; other headers will be ignored")
  end

  headers["host"] = nil

  local idx = find(req_uri, "?", 2, true)
  if idx then
    req_uri = sub(req_uri, 1, idx - 1)
  end

  req_uri = normalize(req_uri, true)

  local match_t = self:select(req_method, req_uri, req_host, req_scheme,
                              nil, nil, nil, nil,
                              sni, headers)
  if not match_t then
    return
  end

  -- debug HTTP request header logic
  if var.http_kong_debug then
    local route = match_t.route
    if route then
      if route.id then
        header["Kong-Route-Id"] = route.id
      end

      if route.name then
        header["Kong-Route-Name"] = route.name
      end
    end

    local service = match_t.service
    if service then
      if service.id then
        header["Kong-Service-Id"] = service.id
      end

      if service.name then
        header["Kong-Service-Name"] = service.name
      end
    end
  end

  return match_t
end


return _M
