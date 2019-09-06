module("luci.controller.scut", package.seeall)
local uci  = require "luci.model.uci".cursor()
local http = require "luci.http"
local fs = require "nixio.fs"
local sys  = require "luci.sys"
local log_file = "/tmp/scut.log"
local log_file_backup = "/tmp/scut.log.backup.log"
function index()
	if not nixio.fs.access("/etc/config/scut") then
		return
	end
		entry({"admin", "network", "scut"},
			alias("admin", "network", "scut", "settings"),
			translate("华工网络认证插件"),
			99
		)
		entry({"admin", "network", "scut", "settings"},
			cbi("scut/scut"),
			translate("设置"),
			10
		).leaf = true
		entry({"admin", "network", "scut", "status"},
			call("action_status"),
			translate("状态"),
			20
		).leaf = true
		entry({"admin", "network", "scut", "logs"},
			call("action_logs"),
			translate("日志"),
			30
		).leaf = true
		entry({"admin", "network", "scut", "about"},
			call("action_about"),
			translate("关于"),
			40
		).leaf = true
		entry({"admin", "network", "scut", "get_log"},
			call("get_log")
		)
end
function get_log()
	local send_log_lines = 60
	local client_log = {}
	if fs.access(log_file) then
		client_log.log = sys.exec("tail -n "..send_log_lines.." " .. log_file)
	else
		client_log.log = "+1s"
	end
	http.prepare_content("application/json")
	http.write_json(client_log)
end
function action_about()
	luci.template.render("scut/about")
end
function action_status()
	luci.template.render("scut/status")
	if luci.http.formvalue("logoff") == "1" then
		luci.sys.call("/etc/init.d/scut stop > /dev/null")
	end
	if luci.http.formvalue("redial") == "1" then
		luci.sys.call("/etc/init.d/scut stop > /dev/null")
		luci.sys.call("/etc/init.d/scut start > /dev/null")
	end
	if luci.http.formvalue("move_tag") == "1" then
		luci.sys.call("sed -i 's/10 *--tagforsed/90    -- change it to 10 to move it back/' /usr/lib/lua/luci/controller/scut.lua")
		luci.sys.call("rm -rf /tmp/luci-*")
	end
end
function action_logs()
	luci.sys.call("touch " .. log_file)
	luci.sys.call("touch " .. log_file_backup)
	local logfile = string.sub(luci.sys.exec("ls " .. log_file),1, -2) or ""
	local backuplogfile = string.sub(luci.sys.exec("ls " .. log_file_backup),1, -2) or ""
	local logs = nixio.fs.readfile(logfile) or ""
	local backuplogs = nixio.fs.readfile(backuplogfile) or ""
	local dirname = "/tmp/scut-log-"..os.date("%Y%m%d-%H%M%S")
	luci.template.render("scut/logs", {
		logs=logs,
		backuplogs=backuplogs,
		dirname=dirname,
		logfile=logfile
	})
	local tar_files = {
		"/etc/config/wireless",
		"/etc/config/network",
		"/etc/config/system",
		"/etc/config/scut",
		"/etc/openwrt_release",
		"/etc/crontabs/root",
		"/etc/config/dhcp",
		"/tmp/dhcp.leases",
		"/etc/rc.local",
		logfile,
		backuplogfile
	}
	luci.sys.call("rm /tmp/scut-log-*.tar")
	luci.sys.call("rm -rf /tmp/scut-log-*")
	luci.sys.call("rm /www/scut-log-*")
	local tar_dir = dirname
	nixio.fs.mkdirr(tar_dir)
	table.foreach(tar_files, function(i, v)
			luci.sys.call("cp "..v.." "..tar_dir)
	end)
	local short_dir = "./"..nixio.fs.basename(tar_dir)
	luci.sys.call("cd /tmp && tar -cvf "..short_dir..".tar "..short_dir.." > /dev/null")
	luci.sys.call("ln -sf "..tar_dir..".tar /www/"..nixio.fs.basename(tar_dir)..".tar")
end
