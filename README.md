# CloudflareLogs





<img align="right" width="150" height="100" src="logo.png">

<br/>

# VS General Prospective for last month


From Cloudflare we have to flavours to download Logs, Logpush and Logpull

- Logpush - Suitable to send to S3 storage or any provider like Datadog, Splunk, NewRelic or IBM cloud useful for further analysis, large amount of data 
- Logpull - Cloudflare Logpull is a REST API for consuming request logs over HTTP, data related to the connecting client, the request path through the Cloudflare network, and the response from the origin web server

```
Logpull is considered a legacy feature and we recommend using Logpush or Logs Engine instead for better performance and functionality.

```

Additionally we have available  - ELS - Enterprise Log Share 7 days



## Download logs via API

The Query used and the fields to download are specified below, we have a Script that takes the initial time and process it with new variables to run per hour and Query with these dates, when reached the end of the day, saves the resulting lines
in one file, creates another file for the next day and so on.

**basic dates Script Example**

```python

from datetime import datetime, timedelta

def increment_dates(start_date, end_date):
    format_str = "%Y-%m-%dT%H:%M:%SZ"
    start_datetime = datetime.strptime(start_date, format_str)
    end_datetime = datetime.strptime(end_date, format_str)

while current_datetime <= end_datetime:
        process_date_start = current_datetime.strftime(format_str)
        current_datetime += timedelta(hours=1)
        process_date_end = current_datetime.strftime(format_str)

start_date = "2023-05-21T00:00:00Z"
end_date = "2023-05-27T23:59:59Z"
increment_dates(start_date, end_date)

```

**Here is the query that we use for retrieving all the fields

```

query = """
            query ListFirewallEvents($zoneTag: String, $filter: FirewallEventsAdaptiveFilter_InputObject, $limit: Int) {
                viewer {
                    zones(filter: { zoneTag: $zoneTag }) {
                        firewallEventsAdaptive(filter: $filter, limit: $limit, orderBy: [datetimeHour_ASC]) {
                            
                            action
                            botScore
                            botScoreSrcName
                            wafXssAttackScore
                            wafSqliAttackScore
                            wafAttackScoreClass
                            ja3Hash
                            source
                            datetimeHour
                            clientIP
                            clientAsn
                            clientCountryName
                            edgeColoName
                            clientRequestHTTPProtocol
                            clientRequestHTTPHost
                            clientRequestPath
                            clientRequestQuery
                            clientRequestScheme
                            clientRequestHTTPMethodName
                            clientRefererHost
                            clientRefererPath
                            clientRefererQuery
                            clientRefererScheme
                            edgeResponseStatus
                            clientASNDescription
                            userAgent
                            kind
                            originResponseStatus
                            ruleId
                            rayName
                        }
                    }
                }
            }
        """

```


The script VS_go_through_time.py Task is to do this for a certain zone. 
When this operation is complete, we see that it creates several csv files.
The Files contain the raw data without headers and separated by commas.

```

18/06/2023  12:05    <DIR>          .
18/06/2023  12:05    <DIR>          ..
19/06/2023  10:41       111.799.684 VS_fire_logs_2023-05-21.csv
19/06/2023  10:45       116.898.301 VS_fire_logs_2023-05-22.csv
19/06/2023  10:48       112.736.292 VS_fire_logs_2023-05-23.csv
19/06/2023  10:51       107.788.560 VS_fire_logs_2023-05-24.csv
19/06/2023  10:55       114.928.834 VS_fire_logs_2023-05-25.csv
19/06/2023  10:58       116.920.366 VS_fire_logs_2023-05-26.csv
19/06/2023  11:02       118.168.866 VS_fire_logs_2023-05-27.csv
19/06/2023  11:02         4.400.771 VS_fire_logs_2023-05-28.csv

```

## Analysis

VS_200_ip_query_path.py

__In this phase we want to descriminate through status codes, get the ips that hits the most and get requestPath.__

We can now use the second Script which goes through the selected file and extracts the 200 status codes and ckecks for the to 10 ips with most requests, it counts them, print them and saves the information in another csv file with the following information
Additionally changing the status code we can explore different type of data.


```
 print(f"IP: {ip}\tRepetitions: {count}")


for ip, count in top_ips.iteritems():
IP: 146.20.232.27       Repetitions: 43101
IP: 146.20.232.29       Repetitions: 42351
IP: 146.20.232.28       Repetitions: 40973
IP: 3.22.29.204 Repetitions: 37547
IP: 173.252.127.11      Repetitions: 49
IP: 173.252.127.18      Repetitions: 49
IP: 173.252.127.118     Repetitions: 49
IP: 173.252.127.119     Repetitions: 49
IP: 173.252.127.16      Repetitions: 47
IP: 173.252.127.15      Repetitions: 46
Findings saved to: E:/VS_firewall_logs/findings.csv

```


Once we have this result and we have the findings.csv 
- Open the findings.csv and separate the column IP,path to two columns remove the ip column
- Save the file with only the path values.


## Find URL Malicious Path

VS_URL_malicious_pattern.py

The script VS_URL_malicious_pattern.py searches for malicious, broken paths and stores them in a file invalid_paths.csv.


Here is an example of patterns we search:

```python

def validate_url_path(url_path):

    pattern = r"^(/[-a-zA-Z0-9@:%._\+~#=]{1,256})*/?$"
    decoded_path = url_path.replace("%5c", "\\").replace("%255c", "\\")
    if re.search(r"(/static/\\?\.\.){3,}", decoded_path):
        return False
    if re.search(r"(password|etc|pwd|admin|administrator|cmd|shell|port)", decoded_path, re.IGNORECASE):
       
       ....


```


Example of paths detected by the script:

```

Invalid Paths

/index.php?page=zip://shell.jpg%23payload.php
/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd
/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
vuln.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
/vsccdisplaypoints/v1/rewardcredits/port/22
/index.php?user=admin
/script.php?page=index.html 


```

<br/><br/>
## 

## Worldwide Overview

Application level Attack activity for the las 4 weeks.

Source to target or target to source connection at a global scale

<br/>

<iframe width="1500" height="400" src="https://radar.cloudflare.com/embed/AttacksCombinedChart?dateRange=28d&chartState=%7B%7D&dateEnd=2023-06-16T14%3A49%3A00.000Z" title="" frameBorder="0"></iframe>

<br/><br/>

# Traffic Volume

<iframe width="1500" height="400" src="https://radar.cloudflare.com/embed/TrafficVolumeXY?dateRange=28d&chartState=%7B%22xy.hiddenSeries%22%3A%5B%5D%2C%22xy.previousVisible%22%3Atrue%7D&dateEnd=2023-06-16T14%3A59%3A00.000Z" title="Cloudflare Radar - Traffic volume" frameBorder="0"></iframe>


# Mitigated traffic sources and attack methods

Distributed Denial of Service
Web Application Firewall
Intelligent Page Routing
Access Restriction
Bot Management
Application Programming Interfaces
Data Loss Prevention

<iframe width="1500" height="400" src="https://radar.cloudflare.com/embed/Layer7DistributionXY?dateRange=28d&chartState=%7B%22xy.hiddenSeries%22%3A%5B%5D%2C%22xy.previousVisible%22%3Atrue%7D&dateEnd=2023-06-16T15%3A03%3A00.000Z" title="Cloudflare Radar - Mitigated traffic sources" frameBorder="0"></iframe>

<iframe width="1500" height="400" src="https://radar.cloudflare.com/embed/Layer3DistributionXY?dateRange=28d&chartState=%7B%22xy.hiddenSeries%22%3A%5B%5D%2C%22xy.previousVisible%22%3Atrue%7D&dateEnd=2023-06-16T15%3A03%3A00.000Z" title="Cloudflare Radar - Attack methods" frameBorder="0"></iframe>
