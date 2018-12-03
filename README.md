# DomainCheck

DomainCheck is designed to assist operators with monitoring changes related to their domain names. This includes negative changes in categorization, VirusTotal detections, and appearances on malware blacklists. DomainCheck currently works only with NameCheap.

DomainCheck pulls a list of domains registered under the provided NameCheap account and then reviews each one to ensure it is ready to be used. This involves checking to see if Whois Guard is enabled, the domain is not expired, the domain is properly categorized, the domain has not been flagged in VirusTotal or tagged with a bad category, and the domain is not blacklisted for spam.

## Information Sources

DomainReview uses the following sources to check the health of a domain name:

* VirusTotal
* Cisco Talos
* Bluecoat
* IBM X-Force
* Fortiguard
* TrendMicro
* OpenDNS
* MXToolbox

Additionally, DomainCheck pulls the latest list of "bad" domains from malwaredomains.com and checks if any of the NameCheap domain names make an appearance.

## Operation Modes

DomainCheck supports two modes:

### Checkup Mode

In checkup mode, DomainCheck pulls the list of domain names and checks each one just once. Once the checks are finished, DomainCheck outputs the data as a csv file. Optionally, if the `--wiki` flag is provided, DomainCheck also produces the results in the markup language understood by Confluence wikis. This markup can be copy and pasted into a wiki to create a nicely formatted table.

To do this, edit a Confluence wiki page, click "Insert," insert a Markup section, and paste in the DomainCheck-generated markup.

#### Usage

The following command checks all domains under the NameCheap account:

`./domaincheck.py checkup --wiki`

This command checks only the domains provided:

`./domaincheck.py checkup --wiki --filter-list domaincheck.com,spectreoops.net`

### Monitor Mode

In monitor mode, DomainCheck will continuously check the domains, either all of the NameCheap domain names or just those the user provides on the command line. A time interval is set (in seconds) and DomainCheck will sleep for that amount of time before re-checking the domains.

Note: The NameCheap API is only queried at the start of a monitoring session, so monitoring must be restarted if new domains are added to the account that also require monitoring.

If the `--slack` flag is provided and a Slack WebHook is configured, DomainCheck will send your configured Slack message whenever an issue (negative categorization, VirusTotal hit, domain added to a watch list) is detected. These messages are sent in addition to warnings displayed in the terminal.

#### Usage

The following command checks the named domains every 1800 seconds (30 minutes) and sends a Slack message if an issue is detected:

`./domaincheck.py monitor --domains domaincheck.com,spectreoops.net -i 1800 --slack`

## Installation

Using pipenv for managing the required libraries is the best option to avoid Python installations getting mixed-up. Do this:

1. Run: `pip3 install --user pipenv` or `python3 -m pip install --user pipenv`
2. Clone DomainCheck's repo.
3. Run: `cd DomainCheck && pipenv install`
4. Start using DomainCheck by running: `pipenv shell`

### Final Configurations

DomainCheck uses a domaincheck.config file. A sample is provided which can be edited and renamed (to remove `.sample` from the end). You will need your NameCheap account and API information, a VirusTotal API key (a free key is fine), and (optional) your Slack WebHook URL. Enter this information into the config file, name it domaincheck.config, and DomainCheck is ready to be used.

## Acknowledgments

Special thanks to [SpecterOps](https://specterops.io) for supporting this project!