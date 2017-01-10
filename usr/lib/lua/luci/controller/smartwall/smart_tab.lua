module("luci.controller.smartwall.smart_tab", package.seeall)
 
function index()
     entry({"admin", "smart_tab"}, firstchild(), "SmartWall", 60).dependent=false  --this adds the top level tab and defaults to the first sub-tab (tab_from_cbi), also it is set to position 30
     entry({"admin", "smart_tab", "tab_from_cbi"}, cbi("smartwall/cbi_tab"), "CBI Tab", 1)  --this adds the first sub-tab that is located in <luci-path>/luci-myapplication/model/cbi/myapp-mymodule and the file is called cbi_tab.lua, also set to first position
     entry({"admin", "smart_tab", "tab_from_view"}, template("smartwall/view_tab"), "View Tab", 2)  --this adds the second sub-tab that is located in <luci-path>/luci-myapplication/view/myapp-mymodule and the file is called view_tab.htm, also set to the second position
end