local mac = "08:00:27:c0:de:9d"

local handle = io.popen("cat /proc/net/arp")
local result = handle:read("*a")
print(result)

local ipList, macList = {}, {}

for word in result:gmatch("(%d+%.%d+%.%d+%.%d+)") do table.insert(ipList, word) end
for word in result:gmatch("(%w+%:%w+%:%w+%:%w+%:%w+%:%w+)") do table.insert(macList, word) end

max = #ipList
count = 0
local ip = ""

while count < max do
	count = count + 1
	if mac == macList[count] then
		ip = ipList[count]
	end
end
handle:close()
