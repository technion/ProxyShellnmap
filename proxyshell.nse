local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
author = {"technion@lolware.net"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Detection rule based on: https://twitter.com/GossiTheDog/status/1424673929382268932
portrule = shortport.http

action = function(host, port)
    local output_info = {}
    local response = http.generic_request(host, port, "GET","/autodiscover/autodiscover.json?@abc.com/owa/?&Email=autodiscover/autodiscover.json%3F@abc.com" )
    if response.header['x-owa-version'] then
        output_info.owa_version = {}
        table.insert(output_info.owa_version, "x-owa-version:" .. response.header['x-owa-version'])
        if response.status == 302 then
        output_info.vuln = "EXCHANGE SERVER IS VULNERABLE"
        else
            output_info.vuln = "No known Exchange vulnerabilities"
        end
    else
        output_info.detected = "Exchange has not been detected"
    end
    return output_info, stdnse.format_output(true, output_info)
end
