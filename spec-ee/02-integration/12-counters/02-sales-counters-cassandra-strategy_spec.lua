local helpers = require "spec.helpers"
local utils = require "kong.tools.utils"
local cassandra_strategy = require("kong.counters.sales.strategies.cassandra")

local LICENSE_DATA_TNAME = "license_data"

for _, strategy in helpers.each_strategy({"cassandra"}) do
  describe("sales counters postgres strategy", function()
    local strategy
    local cluster
    local db
    local uuid
    local snapshot


    setup(function()
      db = select(2, helpers.get_db_utils(strategy))
      strategy = cassandra_strategy:new(db)
      db = db.connector
      cluster  = db.cluster
      uuid     = utils.uuid()
    end)


    before_each(function()
      snapshot = assert:snapshot()
      cluster:execute("TRUNCATE " .. LICENSE_DATA_TNAME)
    end)

    after_each(function()
      snapshot:revert()
    end)


    teardown(function()
      cluster:execute("TRUNCATE " .. LICENSE_DATA_TNAME)
    end)

    describe(":insert_stats()", function()
      it("should flush data to cassandra from one node", function()
        local data = {
          request_count = 10,
          node_id = uuid
        }

        strategy:flush_data(data)

        local res, _ = cluster:execute("select * from " .. LICENSE_DATA_TNAME .. " WHERE node_id = " .. tostring(data.node_id))

        local expected_data = {
            node_id  = uuid,
            req_cnt = 10
        }

        assert.same(expected_data, res[1])
      end)

      it("should flush data to cassandra with more than one row from node", function()
        local data = {
          request_count = 10,
          node_id = uuid
        }

        strategy:flush_data(data)

        local res, _ = cluster:execute("select * from " .. LICENSE_DATA_TNAME .. " WHERE node_id = " .. tostring(data.node_id))

        local expected_data = {
          node_id  = uuid,
          req_cnt = 10
        }

        assert.same(expected_data, res[1])

        local data = {
          request_count = 269,
          node_id = uuid
        }

        strategy:flush_data(data)

        res, _ = cluster:execute("select * from " .. LICENSE_DATA_TNAME .. " WHERE node_id = " .. tostring(data.node_id))

        local expected_data = {
          node_id  = uuid,
          req_cnt = 279
        }

        assert.same(expected_data, res[1])
      end)

      it("should flush data to cassandra from more than one node", function()
        local data = {
          request_count = 10,
          node_id = utils.uuid()
        }

        strategy:flush_data(data)

        local res, _ = cluster:execute("select * from " .. LICENSE_DATA_TNAME .. " WHERE node_id = " .. tostring(data.node_id))

        local expected_data = {
          node_id  = data.node_id,
          req_cnt = 10
        }

        assert.same(expected_data, res[1])

        local data = {
          request_count = 58,
          node_id = utils.uuid()
        }

        strategy:flush_data(data)

        res, _ = cluster:execute("select * from " .. LICENSE_DATA_TNAME .. " WHERE node_id = " .. tostring(data.node_id))

        local expected_data = {
          node_id  = data.node_id,
          req_cnt = 58
        }

        assert.same(expected_data, res[1])
      end)
    end)
  end)
end
