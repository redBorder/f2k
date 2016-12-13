[![Build Status](https://travis-ci.org/redBorder/f2k.svg?branch=master)](https://travis-ci.org/redBorder/f2k)
[![Coverage Status](https://coveralls.io/repos/github/redBorder/f2k/badge.svg?branch=master)](https://coveralls.io/github/redBorder/f2k?branch=master)

# Flow 2 Kafka (f2k)

Netflow to
[Json](http://www.json.org/)/[Kafka](https://kafka.apache.org/) collector.

# Setup
To use it, you only need to do a typical `./configure && make && make install`

# Usage
## Basic usage

The most important configuration parameters are:

- Input/output parameters:
    - `--kafka=127.0.0.1@rb_flow`, broker@topic to send netflow
    - `--collector-port=2055`, Collector port to listen netflow

- Configuration
  - `--rb-config=/opt/rb/etc/f2k/config.json`, File with sensors
    config (see [Sensor config](#sensor-config))

## Sensors config
You need to specify each sensor you want to read netflow from in a JSON file:
```json
{
	"sensors_networks": {
		"4.3.2.1":{
			"observations_id": {
				"1":{
					"enrichment":{
						"sensor_ip":"4.3.2.1",
						"sensor_name":"flow_test",
						"observation_id":1
					}
				}
			}
		}
	}
}
```

With this file, you will be listening for netflow coming from
`4.3.2.1` (this could be a network too, `4.3.2.0/24`), and the JSON output
will be sent with that `sensor_ip`, `sensor_name` and `observation_id` keys.

## Others configuration parameters
### Multi-thread
`--num-threads=N` can be used to specify the number of netflow processing
threads.

### Long flow separation
Use `--separate-long-flows` if you want to divide flow with duration>60s into
minutes. For example, if the flow duration is 1m30s, f2k will send 1 message
containing 2/3 of bytes and pkts for the minute, and 1/3 of bytes and pkts to
the last 30 seconds, like if we had received 2 different flows.

(see [Test 0017](tests/0017-separateLongTimeFlows.c) for more information about
how flow are divided)

### Geo information
`f2k` can add geographic information if you specify
[Maxmind GeoLite Databases](https://dev.maxmind.com/geoip/legacy/geolite/)
location using:
  - `--as-list=/opt/rb/share/GeoIP/asn.dat`,
  - `--country-list=/opt/rb/share/GeoIP/country.dat`,

### Names resolution
You can include more flow information, like many object names, with the option
`--hosts-path=/opt/rb/etc/objects/`. This folder needs to have files with the
provided names in order to f2k read them.

#### Mac vendor information (`mac_vendor`)
With `--mac-vendor-list=mac_vendors` f2k can translate flow source and
destination macs, and they will be sending in JSON output as `in_src_mac_name`,
`out_src_mac_name`, and so on.

The file `mac_vendors` should be like:

    FCF152|Sony Corporation
    FCF1CD|OPTEX-FA CO.,LTD.
    FCF528|ZyXEL Communications Corporation

And you can generate it using `make manuf`, that will obtain it automatically
from [IANA Registration Authority](http://standards.ieee.org/develop/regauth/).

#### Applications/engine ID (`applications`, `engines`)
`f2k` can translate applications and engine ID if you specify a list with them,
like:

- \<hosts-path\>/engines
    ```
    None            0
    IANA-L3         1
    PANA-L3         2
    IANA-L4         3
    PANA-L4         4
    ...
    ```

- \<hosts-path\>/applications
    ```
    3com-amp3                 50332277
    3com-tsmux                50331754
    3pc                       16777250
    914c/g                    50331859
    ...
    ```

#### Hosts, domains, vlan (`hosts`, `http_domains`, `vlans`)
You can include more information about the flow source and destination (
`src_name` and `dst_name`) using a hosts list, using the same format as
`/etc/hosts`. The same can be used with files `vlan`, `domains`, `macs`.

#### Netflow probe nets
You can specify per netflow probe home nets, so they will be taking into account
when solving client/target IP.

You could specify them using `home_nets`:

```json
"sensors_networks": { "4.3.2.0/24":{ "2055":{
	"sensor_name":"test1",
	"sensor_ip":"",
	"home_nets": [
	        {"network":"10.13.30.0/16", "network_name":"users" },
	        {"network":"2001:0428:ce00:0000:0000:0000:0000:0000/48",
	        				"network_name":"users6"}
	],
}}}
```

#### DNS
`f2k` can make reverse DNS in order to obtain some hosts names. To enable them,
you must use:
- `enable-ptr-dns`, general enable
- `dns-cache-size-mb`, DNS cache to not repeat PTR queries
- `dns-cache-timeout-s`, Entry cache timeout

### Template cache
#### Using folder
You can specify a folder to save/load templates using
`--template-cache=/opt/rb/var/f2k/templates`.

#### Using [Apache zookeeper](https://zookeeper.apache.org/)
If you want to use zookeeper to share templates between `f2k` instances, you can
specify zookeeper host using `--zk-host=127.0.0.1:2181` and a proper timeout to
read them with `--zk-timeout=30`. Note that you need to compile `f2k` using
`--enable-zookeeper`.

### [librdkafka](https://github.com/edenhill/librdkafka) options
All [librdkafka options](https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md).
  can be used using `-X` parameter. The argument will be passed directly to
  librdkafka config, so you can use whatever config you need.

  Recommended options are:
- `-X=socket.max.fails=3`,
- `-X=delivery.report.only.error=true`,
