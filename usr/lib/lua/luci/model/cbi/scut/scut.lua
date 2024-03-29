scut = Map(
	"scut",
	"华工网络认证插件设置",
	' <input style="margin: 2px;" class="cbi-button cbi-button-apply" type="button" value="'
	.."第一步：设置Wi-Fi"
	..'" onclick="javascript:location.href=\''
	..luci.dispatcher.build_url("admin/network/wireless/radio0.network1")
	..'\'"/>'
	..' <input style="margin: 2px;" class="cbi-button cbi-button-apply" type="button" value="'
	.."第二步：设置IP"
	..'" onclick="javascript:location.href=\''
	..luci.dispatcher.build_url("admin/network/network/wan")
	..'\'"/>'
	..' <input style="margin: 2px;" class="cbi-button cbi-button-apply" type="button" value="'
	.."第三步：修改路由器管理密码"
	..'" onclick="javascript:location.href=\''
	..luci.dispatcher.build_url("admin/system/admin")
	..'\'"/>'
)
function scut.on_commit(self)
	luci.sys.call("uci set scut.@luci[-1].configured=1")
	luci.sys.call("uci commit")
	luci.sys.call("rm -rf /tmp/luci-*cache")
end
scut_option = scut:section(TypedSection, "option", translate("选项"))
scut_option.anonymous = true
scut_option:option(Flag, "enable", "启用")
scut_client = scut:section(TypedSection, "scut", "用户信息")
scut_client.anonymous = true
scut_client:option(Value, "username", "用户名", "学校提供的用户名")
scut_client:option(Value, "password", "密码").password = true
scut_drcom = scut:section(TypedSection, "drcom", "Drcom设置")
scut_drcom.anonymous = true
scut_drcom_version = scut_drcom:option(Value, "version", "Drcom版本")
scut_drcom_version.rmempty = false
scut_drcom_version:value("4472434f4d0096022a")
scut_drcom_version:value("4472434f4d0096022a00636b2031")
scut_drcom_version:value("4472434f4d00cf072a00332e31332e302d32342d67656e65726963")
scut_drcom_version.default = "4472434f4d0096022a"
scut_drcom_hash = scut_drcom:option(Value, "hash", translate("DrAuthSvr.dll版本"))
scut_drcom_hash.rmempty = false
scut_drcom_hash:value("2ec15ad258aee9604b18f2f8114da38db16efd00")
scut_drcom_hash:value("d985f3d51656a15837e00fab41d3013ecfb6313f")
scut_drcom_hash:value("915e3d0281c3a0bdec36d7f9c15e7a16b59c12b8")
scut_drcom_hash.default = "2ec15ad258aee9604b18f2f8114da38db16efd00"
scut_drcom_server = scut_drcom:option(Value, "server_auth_ip", translate("服务器IP"))
scut_drcom_server.rmempty = false
scut_drcom_server.datatype = "ip4addr"
scut_drcom_server:value("202.38.210.131")
scut_drcom_hostname = scut_drcom:option(Value, "hostname", translate("向服务器发送的主机名"))
scut_drcom_hostname.rmempty = false
local random_hostname = "DESKTOP-"
local randtmp
string.split = function(s, p)
    local rt = {}
    string.gsub(s, '[^'..p..']+', function(w) table.insert(rt, w) end)
    return rt
end
math.randomseed(os.time())
for i = 1, 7 do
	randtmp = math.random(1, 36)
  random_hostname = (randtmp > 10)
    and random_hostname..string.char(randtmp+54)
    or  random_hostname..string.char(randtmp+47)
end
local dhcp_hostnames = string.split(luci.sys.exec("cat /tmp/dhcp.leases|awk {'print $4'}"), "\n") or {}
scut_drcom_hostname:value(random_hostname)
scut_drcom_hostname:value(dhcp_hostnames[1])
scut_drcom_hostname.default = random_hostname
return scut
