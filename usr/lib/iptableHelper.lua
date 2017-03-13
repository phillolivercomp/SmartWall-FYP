require "luci.sys.iptparser"

local mode = 4
local ipt = luci.sys.iptparser.IptParser(mode)
local tables = ipt:chains("filter")
for i, v in pairs(tables) do
	print(v)
end