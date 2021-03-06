local ipc = require "luci.ip"

m = Map("cbi_file", translate("Configuration page"), translate("File out the sections below")) -- cbi_file is the config file in /etc/config

d = m:section(TypedSection, "info", "SQL configuration",
		translate("Specify the details for logging sql details onto an external SQL server "))
a = d:option(Value, "SQLUsername", "Username"); a.optional=false; a.rmempty = false;  -- name is the option in the cbi_file
b = d:option(Value, "SQLPassword", translate("Password")); b.rmemtpy = false; b.password = true;
c = d:option(Value, "SQLIP", "IP"); c.optional=false; c.rmempty = false;

s = m:section(TypedSection, "monitor", translate("Monitored Addresses"),
	translate("Specify the addresses for which smart wall will monitor connections " ..
		"ensuring that they are already statically defined DHCP addresses.") .. "<br />" ..
	translate("Use the <em>Add</em> Button to add a new entry." ))

s.addremove = true
s.anonymous = true

s.template = "cbi/tblsection"

name = s:option(Value, "name", translate("Hostname"))
name.datatype = "hostname"
name.rmempty  = true

mac = s:option(Value, "mac", translate("<abbr title=\"Media Access Control\">MAC</abbr>-Address"))
mac.datatype = "list(macaddr)"
mac.rmempty  = true

ipc.neighbors({ family = 4 }, function(n)
	if n.mac and n.dest then
		mac:value(n.mac, "%s (%s)" %{ n.mac, n.dest:string() })
	end
end)


return m