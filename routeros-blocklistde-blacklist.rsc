# blocklist.de Blacklist Downloader r1bCL.08 for RouterOS v7
# (c) 2023-2025 klayf (contact@klayf.com)

######## Please edit below ########

:local listType {"ssh"; "ftp"; "bots"; "strongips"; "bruteforcelogin"}
:local timeout  "3d 23:30:00"

###################################

:local srvType  "blocklist.de"
:local head     ("[".$srvType." Blacklist] ")
:local getURL   "https://lists.blocklist.de/lists/"
:local errConn  ($head."The server cannot be connected.")
:local errInv   ($head."The received list is empty; please check if the parameter settings are correct. (type: ")
:local finMsg  " addresses have been added to the list."
:local listName "blocklist_reported"

:foreach type in=$listType do={
    :delay 2s
    :local rawData
    :local addrList
    :local endList 0
    :local count4 0
    :local count6 0
    :do {:set rawData ([/tool fetch mode=https http-method=get output=user url=($getURL.$type.".txt") as-value])} on-error={:error $errConn}
    :local sizeList [:len ($rawData->"data")]
    :if ($sizeList!=0) do={
        :set addrList [:deserialize from=dsv delimiter="\n" options=dsv.plain value=($rawData->"data")]
        :if ($sizeList<64512) do={:set $endList ([:len $addrList]-1)} else={:set $endList ([:len $addrList]-2)}
        :for i from=0 to=($endList) do={
            :if ([:toip ($addrList->$i)]) do={
                :do {/ip firewall address-list add list=$listName address=($addrList->$i) comment=("Provided by ".$srvType) timeout=$timeout; :set $count4 ($count4+1)} on-error={}
            }
            :if ([:toip6 ($addrList->$i)]) do={
                :do {/ipv6 firewall address-list add list=$listName address=($addrList->$i) comment=("Provided by ".$srvType) timeout=$timeout; :set $count6 ($count6+1)} on-error={}
            }
        }
        :log info ($head."(type: ".$type.") - [".$count4."] IPv4 and [".$count6."] IPv6".$finMsg)
    } else={:error ($errInv.$type.")")}
}
