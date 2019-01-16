#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This class pulls a list of domains registered under the provided Namecheap account and then
reviews each one to ensure it is ready to be used for an op. This involves checking to see if
Whois Guard is enabled, the domain is not expired, the domain is properly categorized, the
domain has not been flagged in VirusTotal or tagged with a bad category, and the domain is
not blacklisted for spam.

DomainReview checks the domain against VirusTotal, Cisco Talos, Bluecoat, IBM X-Force, Fortiguard, 
TrendMicro, OpeDNS, and MXToolbox. Domains will also be checked against malwaredomains.com's list
of reported domains.

There are options to output the data as a markup table for Confluence, Slack messages, or a
spreadsheet.
"""

import os
import re
import csv
import sys
import json
import shutil
import base64
from time import sleep

import click
import requests
import pytesseract
from PIL import Image
from lxml import etree
from lxml import objectify
from cymon import Cymon
from bs4 import BeautifulSoup

from . import helpers


# Disable requests warnings for things like disabling certificate checking
requests.packages.urllib3.disable_warnings()


class DomainReview(object):
    """Class to pull a list of registered domains belonging to a Namecheap account and then check
    the web reputation of each domain.
    """
    # Confluence markup colors -- *s make bold text
    color_end = r"*{color}"
    red_text = r"{color:red}*"
    green_text = r"{color:green}*"
    orange_text = r"{color:orange}*"
    # API endpoints
    malwaredomains_url = 'http://mirror1.malwaredomains.com/files/justdomains'
    virustotal_domain_report_uri = 'https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}'
    get_domain_list_endpoint = 'https://api.namecheap.com/xml.response?ApiUser={}&ApiKey={}&UserName={}&Command=namecheap.domains.getList&ClientIp={}&PageSize={}'
    get_dns_list_endpoint = 'https://api.namecheap.com/xml.response?ApiUser={}&ApiKey={}&UserName={}&Command=namecheap.domains.dns.getHosts&ClientIp={}&SLD={}&TLD={}'
    # Categories we don't want to see
    # These are lowercase to avoid inconsistencies with how each service might return the categories
    blacklisted = ['phishing', 'web ads/analytics', 'suspicious', 'shopping', 'placeholders', 
                   'pornography', 'spam', 'gambling', 'scam/questionable/illegal', 
                   'malicious sources/malnets']
    # Variables for web browsing
    useragent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36'
    session = requests.Session()
    # Additional settings
    request_delay = 20

    def __init__(self):
        """Everything that needs to be setup when a new DomainReview object is created goes here."""
        try:
            self.slack_emoji = helpers.config_section_map('Slack')['slack_emoji']
            self.slack_channel = helpers.config_section_map('Slack')['slack_channel']
            self.slack_username = helpers.config_section_map('Slack')['slack_username']
            self.slack_webhook_url = helpers.config_section_map('Slack')['slack_webhook_url']
            self.slack_alert_target = helpers.config_section_map('Slack')['slack_alert_target']
            self.slack_capable = True
        except Exception as error:
            self.slack_capable = False
            click.secho('[!] Could not load a Slack config from domaincheck.config.', fg='red')
            click.secho('L.. Details: {}'.format(error), fg='red')
        try:
            self.client_ip = helpers.config_section_map('Namecheap')['client_ip']
            self.namecheap_api_key = helpers.config_section_map('Namecheap')['namecheap_api_key']
            self.namecheap_username = helpers.config_section_map('Namecheap')['namecheap_username']
            self.virustotal_api_key = helpers.config_section_map('VirusTotal')['virustotal_api_key']
            self.namecheap_page_size = helpers.config_section_map('Namecheap')['namecheap_page_size']
            self.namecheap_api_username = helpers.config_section_map('Namecheap')['namecheap_api_username']
        except Exception as error:
            click.secho('[!] Could not load all necessary API information from the domaincheck.config.', fg='red')
            click.secho('L.. Details: {}'.format(error), fg='red')
            exit()

    def get_domain_list(self, csv_file=None):
        """Fetch a list of registered domains for the specified Namecheap account. A valid API key, 
        username, and whitelisted IP address must be used. The returned XML contains entries for
        domains like this:
        
        <RequestedCommand>namecheap.domains.getList</RequestedCommand>
        <CommandResponse Type="namecheap.domains.getList">
            <DomainGetListResult>
                <Domain ID="127"
                Name="domain1.com"
                User="owner"
                Created="02/15/2016"
                Expires="02/15/2022"
                IsExpired='False'
                IsLocked='False'
                AutoRenew='False'
                WhoisGuard="ENABLED"
                IsPremium="true"
                IsOurDNS="true"/>
            </DomainGetListResult>
        
        An optional csv file can be provided with domain information instead of using the Namecheap
        API to pull the data.
        """
        domains_list = []
        if csv_file:
            click.secho('[+] Will try to use the provided csv file instead of accessing the Namecheap API.', fg='green')
            pass
            # TODO
        else:
            try:
                # The Namecheap API call requires both usernames, a key, and a whitelisted IP
                req = self.session.get(self.get_domain_list_endpoint.format(self.namecheap_api_username, 
                                    self.namecheap_api_key, self.namecheap_username, self.client_ip, 
                                    self.namecheap_page_size))
                # Check if request returned a 200 OK
                if req.ok:
                    # Convert Namecheap XML into an easy to use object for iteration
                    root = objectify.fromstring(req.content)
                    # Check the status to make sure it says "OK"
                    namecheap_api_result = root.attrib['Status']
                    if namecheap_api_result == 'OK':
                        # Get all "Domain" node attributes from the XML response
                        click.secho('[+] Namecheap returned status "{}"'.format(namecheap_api_result), fg='green')
                        for domain in root.CommandResponse.DomainGetListResult.Domain:
                            domains_list.append(domain.attrib)
                    elif namecheap_api_result == 'ERROR':
                        click.secho('[!] Namecheap returned an "ERROR" response, so no domains were returned.', fg='red')
                        if 'Invalid request IP' in req.text:
                            click.secho('L.. You are not connecting to Namecheap using your whitelisted IP address.', fg='red')
                        click.secho('Full Response:\n{}'.format(req.text), fg='red')
                    else:
                        click.secho('[!] Namecheap did not return an "OK" response, so no domains were returned.', fg='red')
                        click.secho('Full Response:\n{}'.format(req.text), fg='red')
                else:
                    click.secho('[!] Namecheap API request failed. Namecheap did not return a 200 response.', fg='red')
                    click.secho('L.. API request returned status "{}"'.format(req.status_code), fg='red')
            except Exception as error:
                click.secho('[!] Namecheap API request failed with error: {}'.format(error), fg='red')
            # There's a chance no domains are returned if the provided usernames don't have any domains
            if domains_list:
                return domains_list
            else:
                click.secho('[!] No domains were returned for the provided account! Exiting...', fg='red')
                exit()

    def get_domain_dns_namecheap(self, domain):
        """Fetch the NameCheap DNS records for the provided domain registered to the specified
        Namecheap account. A valid API key, username, and whitelisted IP address must be used.
        The returned XML contains entries for domains like this:

        <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
        <CommandResponse Type="namecheap.domains.dns.getHosts">
            <DomainDNSGetHostsResult Domain="domain.com" IsUsingOurDNS="true">
                <Host HostId="12"
                Name="@" Type="A"
                Address="1.2.3.4"
                MXPref="10"
                TTL="1800" />
            </DomainDNSGetHostsResult>
        </CommandResponse>
        """
        # NameCheap requires DNS look-ups to provide the domain and the domain's TLD in separate parameters
        domain_name = domain.split('.')[0]
        domain_tld = domain.split('.')[1]
        dns_dict = {}
        try:
            # The Namecheap API call requires both usernames, a key, and a whitelisted IP
            req = self.session.get(self.get_dns_list_endpoint.format(self.namecheap_api_username, 
                                    self.namecheap_api_key, self.namecheap_username, self.client_ip, 
                                    domain_name, domain_tld))
            # Check if request returned a 200 OK
            if req.ok:
                # Convert Namecheap XML into an easy to use object for iteration
                root = objectify.fromstring(req.content)
                # Check the status to make sure it says "OK"
                namecheap_api_result = root.attrib['Status']
                if namecheap_api_result == 'OK':
                    # Get all "Domain" node attributes from the XML response
                    dns_dict[domain] = {}
                    dns_dict[domain]['Status'] = 'OK'
                    dns_dict[domain]['Records'] = {}
                    for host in root.CommandResponse.DomainDNSGetHostsResult.host:
                        dns_dict[domain]['Records'][host.attrib['Name']] = "{} {}".format(host.attrib['Type'], host.attrib['Address'])
                elif namecheap_api_result == 'ERROR':
                    dns_dict[domain] = {}
                    dns_dict[domain]['Status'] = 'ERROR'
                else:
                    dns_dict[domain] = {}
                    dns_dict[domain]['Status'] = 'ERROR'
            else:
                dns_dict[domain] = {}
                dns_dict[domain]['Status'] = 'ERROR'
        except Exception as error:
            dns_dict[domain] = {}
            dns_dict[domain]['Status'] = 'ERROR'
        return dns_dict
    
    def get_domain_dns_python(self, domain):
        """Fetch a domain's DNS records using Python DNS instead of the Namecheap API."""
        pass
        # TODO

    def check_virustotal(self, domain, ignore_case=False):
        """Check the provided domain name with VirusTotal. VirusTotal's API is case sensitive, so
        the domain will be converted to lowercase by default. This can be disabled using the
        ignore_case parameter.

        This uses the VirusTotal /domain/report endpoint:

        https://developers.virustotal.com/v2.0/reference#domain-report
        """
        if not ignore_case:
            domain = domain.lower()
        req = self.session.get(self.virustotal_domain_report_uri.format(self.virustotal_api_key, domain))
        vt_data = req.json()

        return vt_data

    def check_talos(self, domain):
        """Check the provided domain's category as determined by Cisco Talos."""
        categories = []
        cisco_talos_uri = 'https://talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F&query_entry={}&offset=0&order=ip+asc'
        headers = {'User-Agent': self.useragent, 
                   'Referer': 'https://www.talosintelligence.com/reputation_center/lookup?search=' + domain}
        try:
            req = self.session.get(cisco_talos_uri.format(domain), headers=headers)
            if req.ok:
                json_data = req.json()
                category = json_data['category']
                if category:
                    categories.append(json_data['category']['description'])
                else:
                    categories.append('Uncategorized')
            else:
                click.secho('\n[!] Cisco Talos check request failed. Talos did not return a 200 response.', fg='red')
                click.secho('L.. Request returned status "{}"'.format(req.status_code), fg='red')
        except Exception as error:
                click.secho('\n[!] Cisco Talos request failed: {}'.format(error), fg='red')
        return categories

    def check_ibm_xforce(self, domain):
        """Check the provided domain's category as determined by IBM X-Force."""
        categories = []
        xforce_uri = 'https://exchange.xforce.ibmcloud.com/url/{}'.format(domain)
        headers = {'User-Agent': self.useragent, 
                   'Accept': 'application/json, text/plain, */*', 
                   'x-ui': 'XFE', 
                   'Origin': xforce_uri, 
                   'Referer': xforce_uri}
        xforce_api_uri = 'https://api.xforce.ibmcloud.com/url/{}'.format(domain)
        try:
            req = self.session.get(xforce_api_uri, headers=headers, verify=False)
            if req.ok:
                response = req.json()
                if not response['result']['cats']:
                    categories.append('Uncategorized')
                else:
                    temp = ''
                    # Parse all dictionary keys and append to single string to get Category names
                    for key in response['result']['cats']:
                        categories.append(key)
                    # categories = "{0}(Score: {1})".format(temp, str(response['result']['score']))
            # IBM X-Force returns a 404 with {"error":"Not found."} if the domain is unknown
            elif req.status_code == 404:
                categories.append('Unknown')
            else:
                click.secho('\n[!] IBM X-Force check request failed. X-Force did not return a 200 response.', fg='red')
                click.secho('L.. Request returned status "{}"'.format(req.status_code), fg='red')
        except:
            click.secho('\n[!] IBM X-Force request failed: {}'.format(error), fg='red')
        return categories

    def check_fortiguard(self, domain):
        """Check the provided domain's category as determined by Fortiguard Webfilter."""
        categories = []
        fortiguard_uri = 'https://fortiguard.com/webfilter?q=' + domain
        headers = {'User-Agent': self.useragent, 
                   'Origin':'https://fortiguard.com', 
                   'Referer':'https://fortiguard.com/webfilter'}
        try:
            req = self.session.get(fortiguard_uri, headers=headers)
            if req.ok:
                """
                Example HTML result:
                <div class="well">
                    <div class="row">
                        <div class="col-md-9 col-sm-12">
                            <h4 class="info_title">Category: Education</h4>
                """
                # TODO: Might be best to BS4 for this rather than regex
                cat = re.findall('Category: (.*?)" />', req.text, re.DOTALL)
                categories.append(cat[0])
            else:
                click.secho('\n[!] Fortiguard check request failed. Fortiguard did not return a 200 response.', fg='red')
                click.secho('L.. Request returned status "{}"'.format(req.status_code), fg='red')
        except Exception as error:
            click.secho('\n[!] Fortiguard request failed: {}'.format(error), fg='red')
        return categories

    def check_bluecoat(self, domain, ocr=True):
        """Check the provided domain's category as determined by Symantec Bluecoat."""
        categories = []
        bluecoart_uri = 'https://sitereview.bluecoat.com/resource/lookup'
        post_data = {'url': domain, 'captcha': ''}
        headers = {'User-Agent': self.useragent, 
                   'Content-Type': 'application/json; charset=UTF-8', 
                   'Referer': 'https://sitereview.bluecoat.com/lookup'}
        try:
            response = self.session.post(bluecoart_uri, headers=headers, json=post_data, verify=False)
            root = etree.fromstring(response.text)
            for node in root.xpath("//CategorizationResult//categorization//categorization//name"):
                categories.append(node.text)
            if 'captcha' in categories:
                if ocr:
                    # This request is also performed by a browser, but is not needed for our purposes
                    click.secho('[*] Received a CAPTCHA challenge from Bluecoat...', fg='yellow')
                    captcha = self.solve_captcha('https://sitereview.bluecoat.com/resource/captcha.jpg', self.session)
                    if captcha:
                        b64captcha = base64.urlsafe_b64encode(captcha.encode('utf-8')).decode('utf-8')
                        # Send CAPTCHA solution via GET since inclusion with the domain categorization request doesn't work anymore
                        click.secho('[*] Submitting an OCRed CAPTCHA text to Bluecoat...', fg='yellow')
                        captcha_solution_url = 'https://sitereview.bluecoat.com/resource/captcha-request/{0}'.format(b64captcha)
                        response = self.session.get(url=captcha_solution_url, headers=headers, verify=False)
                        # Try the categorization request again
                        response = self.session.post(url, headers=headers, json=postData, verify=False)
                        response_json = json.loads(response.text)
                        if 'errorType' in response_json:
                            click.secho('[!] CAPTCHA submission was apparently incorrect!', fg='red')
                            categories = response_json['errorType']
                        else:
                            click.secho('[!] CAPTCHA submission was accepted!', fg='green')
                            categories = response_json['categorization'][0]['name']
                    else:
                        click.secho('\n[!] Failed to solve BlueCoat CAPTCHA with OCR. Manually solve at: "https://sitereview.bluecoat.com/sitereview.jsp"', fg='red')
                else:
                    click.secho('\n[!] Failed to solve BlueCoat CAPTCHA with OCR. Manually solve at: "https://sitereview.bluecoat.com/sitereview.jsp"', fg='red')
        except Exception as error:
            click.secho('\n[!] Bluecoat request failed: {0}'.format(error), fg='red')
        return categories

    def solve_captcha(self, url, session):
        """Solve a Bluecoat CAPTCHA for the provided session."""
        # Downloads CAPTCHA image and saves to current directory for OCR with tesseract
        # Returns CAPTCHA string or False if error occurred
        jpeg = 'captcha.jpg'
        headers = {'User-Agent': self.useragent}
        try:
            response = session.get(url=url, headers=headers, verify=False, stream=True)
            if response.status_code == 200:
                with open(jpeg, 'wb') as f:
                    response.raw.decode_content = True
                    shutil.copyfileobj(response.raw, f)
            else:
                click.secho('[!] Failed to download the Bluecoat CAPTCHA.', fg='red')
                return False
            # Perform basic OCR without additional image enhancement
            text = pytesseract.image_to_string(Image.open(jpeg))
            text = text.replace(" ', '").replace("[', 'l").replace("'', '")
            # Remove CAPTCHA file
            try:
                os.remove(jpeg)
            except OSError:
                pass
            return text
        except Exception as error:
            click.secho('[!] Error processing the Bluecoat CAPTCHA.'.format(error), fg='red')
            return False

    def check_mxtoolbox(self, domain):
        """Check if the provided domain is blacklisted as spam as determined by MX Toolkit."""
        issues = []
        mxtoolbox_url = 'https://mxtoolbox.com/Public/Tools/BrandReputation.aspx'
        headers = {'User-Agent': self.useragent, 
                   'Origin': mxtoolbox_url, 
                   'Referer': mxtoolbox_url}  
        try:
            response = self.session.get(url=mxtoolbox_url, headers=headers)
            soup = BeautifulSoup(response.content, 'lxml')
            viewstate = soup.select('input[name=__VIEWSTATE]')[0]['value']
            viewstategenerator = soup.select('input[name=__VIEWSTATEGENERATOR]')[0]['value']
            eventvalidation = soup.select('input[name=__EVENTVALIDATION]')[0]['value']
            data = {
                    '__EVENTTARGET':'', 
                    '__EVENTARGUMENT':'', 
                    '__VIEWSTATE':viewstate, 
                    '__VIEWSTATEGENERATOR':viewstategenerator, 
                    '__EVENTVALIDATION':eventvalidation, 
                    'ctl00$ContentPlaceHolder1$brandReputationUrl':domain, 
                    'ctl00$ContentPlaceHolder1$brandReputationDoLookup':'Brand Reputation Lookup', 
                    'ctl00$ucSignIn$hfRegCode':'missing', 
                    'ctl00$ucSignIn$hfRedirectSignUp':'/Public/Tools/BrandReputation.aspx', 
                    'ctl00$ucSignIn$hfRedirectLogin':'', 
                    'ctl00$ucSignIn$txtEmailAddress':'', 
                    'ctl00$ucSignIn$cbNewAccount':'cbNewAccount', 
                    'ctl00$ucSignIn$txtFullName':'', 
                    'ctl00$ucSignIn$txtModalNewPassword':'', 
                    'ctl00$ucSignIn$txtPhone':'', 
                    'ctl00$ucSignIn$txtCompanyName':'', 
                    'ctl00$ucSignIn$drpTitle':'', 
                    'ctl00$ucSignIn$txtTitleName':'', 
                    'ctl00$ucSignIn$txtModalPassword':''
            }
            response = self.session.post(url=mxtoolbox_url, headers=headers, data=data)
            soup = BeautifulSoup(response.content, 'lxml')
            if soup.select('div[id=ctl00_ContentPlaceHolder1_noIssuesFound]'):
                issues.append('No issues found')
            else:
                if soup.select('div[id=ctl00_ContentPlaceHolder1_googleSafeBrowsingIssuesFound]'):
                    issues.append('Google SafeBrowsing Issues Found.')
                if soup.select('div[id=ctl00_ContentPlaceHolder1_phishTankIssuesFound]'):
                    issues.append('PhishTank Issues Found')
        except Exception as error:
            click.secho('\n[!] Error retrieving Google SafeBrowsing and PhishTank reputation!', fg='red')
        return issues

    def check_cymon(self, target):
        """Get reputation data from Cymon.io for target IP address. This returns two dictionaries
        for domains and security events.

        A Cymon API key is not required, but is recommended.
        """
        try:
            req = self.session.get(url='https://cymon.io/' + target, verify=False)
            if req.status_code == 200:
                if 'IP Not Found' in req.text:
                    return False
                else:
                    return True
            else:
                return False
        except Exception:
            return False

    def check_opendns(self, domain):
        """Check the provided domain's category as determined by the OpenDNS community."""
        categories = []
        opendns_uri = 'https://domain.opendns.com/{}'
        headers = {'User-Agent': self.useragent}
        try:
            response = self.session.get(opendns_uri.format(domain), headers=headers, verify=False)
            soup = BeautifulSoup(response.content, 'lxml')
            tags = soup.find('span', {'class':'normal'})
            if tags:
                categories = tags.text.strip().split(', ')
            else:
                categories.append('No Tags')
        except Exception as error:
            click.secho('\n[!] OpenDNS request failed: {0}'.format(error), fg='red')
        return categories

    def check_trendmicro(self, domain):
        """Check the provided domain's category as determined by the Trend Micro."""
        categories = []
        trendmicro_uri = 'https://global.sitesafety.trendmicro.com/'
        trendmicro_stage_1_uri = 'https://global.sitesafety.trendmicro.com/lib/idn.php'
        trendmicro_stage_2_uri = 'https://global.sitesafety.trendmicro.com/result.php'
        headers = {'User-Agent': self.useragent}
        headers_stage_1 = {
                           'Host': 'global.sitesafety.trendmicro.com', 
                           'Accept': '*/*', 
                           'Origin': 'https://global.sitesafety.trendmicro.com', 
                           'X-Requested-With': 'XMLHttpRequest', 
                           'User-Agent': self.useragent, 
                           'Content-Type': 'application/x-www-form-urlencoded', 
                           'Referer': 'https://global.sitesafety.trendmicro.com/index.php', 
                           'Accept-Encoding': 'gzip, deflate', 
                           'Accept-Language': 'en-US, en;q=0.9'
                          }
        headers_stage_2 = {
                           'Origin': 'https://global.sitesafety.trendmicro.com', 
                           'Content-Type': 'application/x-www-form-urlencoded', 
                           'User-Agent': self.useragent, 
                           'Accept': 'text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, image/apng, */*;q=0.8', 
                           'Referer': 'https://global.sitesafety.trendmicro.com/index.php', 
                           'Accept-Encoding': 'gzip, deflate', 
                           'Accept-Language': 'en-US, en;q=0.9'
                          }
        data_stage_1 = {'url': domain}
        data_stage_2 = {'urlname': domain, 
                        'getinfo': 'Check Now'
                       }
        try:
            response = self.session.get(trendmicro_uri, headers=headers)
            response = self.session.post(trendmicro_stage_1_uri, headers=headers_stage_1, data=data_stage_1)
            response = self.session.post(trendmicro_stage_2_uri, headers=headers_stage_2, data=data_stage_2)
            # Check if session was redirected to /captcha.php
            if 'captcha' in response.url:
                click.secho('[!] TrendMicro responded with a reCAPTCHA, so cannot proceed with TrendMicro.', fg='red')
                click.secho('L.. You can try solving it yourself: https://global.sitesafety.trendmicro.com/captcha.php', fg='red')
            else:
                soup = BeautifulSoup(response.content, 'lxml')
                tags = soup.find('div', {'class':'labeltitlesmallresult'})
                if tags:
                    categories = tags.text.strip().split(', ')
                else:
                    categories.append('Uncategorized')
        except Exception as error:
            click.secho('\n[!] Trend Micro request failed: {0}'.format(error), fg='red')
        return categories

    def download_malware_domains(self):
        """Downloads the malwaredomains.com list of malicious domains."""
        headers = {'User-Agent': self.useragent}
        response = self.session.get(url=self.malwaredomains_url, headers=headers, verify=False)
        malware_domains = response.text
        if response.status_code == 200:
            return malware_domains
        else:
            click.secho('[!] Error reaching: {}, Status: {}'.format(self.malwaredomains_url, response.status_code), fg='red')
            return None

    def check_domain_status(self, domains_list, filter_list=None):
        """Check the status of each domain in the provided list collected from Namecheap's domainList
        API. Each domain will be checked to ensure WHOIS privacy is enabled, the domain has not expired, 
        and the domain is not flagged/blacklisted. A domain will be considered burned if VirusTotal
        returns detections for the domain or one of the domain's categories appears in the list of
        bad categories.

        VirusTotal allows 4 requests every 1 minute, so a minimum of sleep(20) is recommended.
        """
        if filter_list:
            num_of_domains = len(filter_list)
        else:
            num_of_domains = len(domains_list)
        lab_results = {}
        malware_domains = self.download_malware_domains()
        with click.progressbar(domains_list, 
                               label='Checking domains', 
                               length=num_of_domains) as bar:
            for item in bar:
                domain = item['Name']
                creation_date = item['Created']
                expiration_date = item['Expires']
                domain_categories = []
                burned_explanations = []
                # If there's a filter list, continue past any domain not in it
                if filter_list:
                    if not domain in filter_list:
                        continue
                # Default values: Healthy until proven burned
                burned = False
                burned_dns = False
                health = 'Healthy'
                health_dns = 'Healthy'
                whoisguard = 'Enabled'
                expired = 'False'
                # Check the Namecheap status of the domain
                if not item['WhoisGuard'].lower() == 'enabled':
                    whoisguard = item['WhoisGuard'].upper()
                else:
                    expired = 'Enabled'
                if not item['IsExpired'].lower() == 'False':
                    expired = item['IsExpired'].upper()
                else:
                    expired = 'False'
                # Check if domain is flagged for malware
                if malware_domains:
                    if domain in malware_domains:
                        click.secho('\n[!] {}: Identified as a known malware domain (malwaredomains.com)!'.format(domain), fg='red')
                        burned = True
                        health = 'Burned'
                        burned_explanations.append('Flagged by malwaredomains.com')
                # Check domain name with VirusTotal
                vt_results = self.check_virustotal(item['Name'])
                if 'categories' in vt_results:
                    domain_categories = vt_results['categories']
                # Check if VirusTotal has any detections for URLs or samples
                if 'detected_downloaded_samples' in vt_results:
                    if len(vt_results['detected_downloaded_samples']) > 0:
                        click.secho('\n[!] {}: Identified as having a downloaded sample on VirusTotal!'.format(domain), fg='red')
                        burned = True
                        health = 'Burned'
                        burned_explanations.append('Tied to a VirusTotal detected malware sample')
                if 'detected_urls' in vt_results:
                    if len(vt_results['detected_urls']) > 0:
                        click.secho('\n[!] {}: Identified as having a URL detection on VirusTotal!'.format(domain), fg='red')
                        burned = True
                        health = 'Burned'
                        burned_explanations.append('Tied to a VirusTotal detected URL')
                # Get passive DNS results from VirusTotal JSON
                ip_addresses = []
                if 'resolutions' in vt_results:
                    for address in vt_results['resolutions']:
                        ip_addresses.append({'address':address['ip_address'], 'timestamp':address['last_resolved'].split(" ")[0]})
                bad_addresses = []
                for address in ip_addresses:
                    if self.check_cymon(address['address']):
                        burned_dns = True
                        bad_addresses.append(address['address'] + '/' + address['timestamp'])
                if burned_dns:
                    click.secho('\n[*] {}: Identified as pointing to suspect IP addresses (VirusTotal passive DNS).'.format(domain), fg='yellow')
                    health_dns = 'Flagged DNS ({})'.format(', '.join(bad_addresses))
                # Collect categories from the other sources
                xforce_results = self.check_ibm_xforce(domain)
                domain_categories.extend(xforce_results)
                talos_results = self.check_talos(domain)
                domain_categories.extend(talos_results)
                bluecoat_results = self.check_bluecoat(domain)
                domain_categories.extend(bluecoat_results)
                fortiguard_results = self.check_fortiguard(domain)
                domain_categories.extend(fortiguard_results)
                opendns_results = self.check_opendns(domain)
                domain_categories.extend(opendns_results)
                trendmicro_results = self.check_trendmicro(domain)
                domain_categories.extend(trendmicro_results)
                mxtoolbox_results = self.check_mxtoolbox(domain)
                domain_categories.extend(domain_categories)
                # Make categories unique
                domain_categories = list(set(domain_categories))
                # Check if any categopries are suspect
                bad_cats = []
                for category in domain_categories:
                    if category.lower() in self.blacklisted:
                        bad_cats.append(category.capitalize())
                if bad_cats:
                    click.secho('\n[!] {}: is tagged with a bad category, {}!'.format(domain, ', '.join(bad_cats)), fg='red')
                    burned = True
                    health = 'Burned'
                    burned_explanations.append('Tagged with a bad category')
                # Collect the DNS records
                dns_records = []
                namecheap_records = self.get_domain_dns_namecheap(domain)
                if namecheap_records[domain]['Status'] == 'OK':
                    for key, value in namecheap_records[domain]['Records'].items():
                        dns_records.append('{} {}'.format(key, value))
                # Assemble the dictionary to return for this domain
                lab_results[domain] = {}
                lab_results[domain]['dns'] = {}
                lab_results[domain]['categories'] = {}
                lab_results[domain]['health'] = health
                lab_results[domain]['burned_explanation'] = ', '.join(burned_explanations)
                lab_results[domain]['health_dns'] = health_dns
                lab_results[domain]['creation'] = creation_date
                lab_results[domain]['expiration'] = expiration_date
                lab_results[domain]['expired'] = expired
                lab_results[domain]['whoisguard'] = whoisguard
                lab_results[domain]['categories']['all'] = domain_categories
                lab_results[domain]['categories']['talos'] = talos_results
                lab_results[domain]['categories']['xforce'] = xforce_results
                lab_results[domain]['categories']['opendns'] = opendns_results
                lab_results[domain]['categories']['bluecoat'] = bluecoat_results
                lab_results[domain]['categories']['mxtoolbox'] = mxtoolbox_results
                lab_results[domain]['categories']['trendmicro'] = trendmicro_results
                lab_results[domain]['categories']['fortiguard'] = fortiguard_results
                lab_results[domain]['dns'] = dns_records
                # Sleep for a while for VirusTotal's API
                sleep(self.request_delay)
        return lab_results

    def output_csv(self, lab_results):
        """Accepts the results from check_domain_status() and creates a CSV file ."""
        csv_headers = ['Domain', 'Registrar', 'Domain Health', 'DNS Health', 'DNS', 'Whois Privacy',
                       'Creation', 'Expiration', 'All', 'IBM X-Force', 'Talos', 'Bluecoat',
                       'Fortiguard', 'OpenDNS', 'TrendMicro', 'MX Toolbox', 'Note']
        with open('domain_health.csv', mode='w') as report:
            report_writer = csv.writer(report, delimiter=',' , quotechar='"', quoting=csv.QUOTE_MINIMAL)
            report_writer.writerow(csv_headers)
            for domain in lab_results:
                health = lab_results[domain]['health']
                health_dns = lab_results[domain]['health_dns']
                whois = lab_results[domain]['whoisguard']
                creation = lab_results[domain]['creation']
                expiration = lab_results[domain]['expiration']
                all_cats = lab_results[domain]['categories']['all']

                talos = lab_results[domain]['categories']['talos']
                if not talos:
                    talos = ['UNKNOWN/ERROR']

                xforce = lab_results[domain]['categories']['xforce']
                if not xforce:
                    xforce = ['UNKNOWN/ERROR']

                bluecoat = lab_results[domain]['categories']['bluecoat']
                if not bluecoat:
                    bluecoat = ['UNKNOWN/ERROR']

                opendns = lab_results[domain]['categories']['opendns']
                if not opendns:
                    opendns = ['UNKNOWN/ERROR']

                trendmicro = lab_results[domain]['categories']['trendmicro']
                if not trendmicro:
                    trendmicro = ['UNKNOWN/ERROR']

                mxtoolbox = lab_results[domain]['categories']['mxtoolbox']
                if not mxtoolbox:
                    mxtoolbox = ['UNKNOWN/ERROR']

                fortiguard = lab_results[domain]['categories']['fortiguard']
                if not fortiguard:
                    fortiguard = ['UNKNOWN/ERROR']

                parsed_cats = []
                for category in all_cats:
                    parsed_cats.append(category.capitalize())
                parsed_cats = list(set(parsed_cats))

                dns_records = lab_results[domain]['dns']
                if not dns_records:
                    dns_records = ['NO RESULTS']

                burned_explanations = lab_results[domain]['burned_explanation']
                if not burned_explanations:
                    burned_explanations = ['']

                report_writer.writerow([domain, 'Namecheap', health, health_dns, ', '.join(dns_records),
                                        whois, creation, expiration, ', '.join(parsed_cats),
                                        ', '.join(xforce), ', '.join(talos), ', '.join(bluecoat),
                                        ', '.join(fortiguard), ', '.join(opendns),
                                        ', '.join(trendmicro), ', '.join(mxtoolbox),
                                        burned_explanations]
                                      )

    def print_confluence_table(self, lab_results):
        """Accepts the results from check_domain_status() and generates a table of results using
        Confluence markup syntax. The click.sechoed results can be copied and pasted into a Confluence
        wiki page to generate a table.

        || = Header cells, bolded text
        |  = Separates cells
        """
        table_headers = '||Domain||Domain Health||DNS Health||DNS||Whois Privacy||Creation||Expiration||All Categories||IBM X-Force||Talos||Bluecoat||Fortiguard||OpenDNS||Trend Micro||MX Toolbox'
        click.secho('[+] The following text should be pasted into your wiki:', fg='green')
        click.secho('[+] click "Insert" and insert a Markup section and paste in this markup:\n', fg='green')
        click.secho(table_headers, fg='yellow')
        for domain in lab_results:
            creation = lab_results[domain]['creation']
            expiration = lab_results[domain]['expiration']

            health = lab_results[domain]['health']
            if health == 'Healthy':
                health = self.green_text + health + self.color_end
            else:
                health = self.red_text + health + self.color_end

            health_dns = lab_results[domain]['health_dns']
            if health_dns == 'Healthy':
                health_dns = self.green_text + health_dns + self.color_end
            else:
                health_dns = self.red_text + health_dns + self.color_end

            expired = lab_results[domain]['expired']
            if expired == 'False':
                expiration = self.green_text + expiration + self.color_end
            else:
                expiration = self.red_text + expiration + self.color_end

            whois = lab_results[domain]['whoisguard']
            if whois == 'Enabled':
                whois = self.green_text + whois + self.color_end
            else:
                whois = self.red_text + whois + self.color_end

            talos = lab_results[domain]['categories']['talos']
            if not talos:
                talos = [self.red_text + 'UNKNOWN/ERROR' + self.color_end]

            xforce = lab_results[domain]['categories']['xforce']
            if not xforce:
                xforce = [self.red_text + 'UNKNOWN/ERROR' + self.color_end]

            bluecoat = lab_results[domain]['categories']['bluecoat']
            if not bluecoat:
                bluecoat = [self.red_text + 'UNKNOWN/ERROR' + self.color_end]

            fortiguard = lab_results[domain]['categories']['fortiguard']
            if not fortiguard:
                fortiguard = [self.red_text + 'UNKNOWN/ERROR' + self.color_end]

            opendns = lab_results[domain]['categories']['opendns']
            if not opendns:
                opendns = [self.red_text + 'UNKNOWN/ERROR' + self.color_end]

            trendmicro = lab_results[domain]['categories']['trendmicro']
            if not trendmicro:
                trendmicro = [self.red_text + 'UNKNOWN/ERROR' + self.color_end]

            mxtoolbox = lab_results[domain]['categories']['mxtoolbox']
            if not mxtoolbox:
                mxtoolbox = [self.red_text + 'UNKNOWN/ERROR' + self.color_end]

            # Review the categories for this domain
            all_cats = lab_results[domain]['categories']['all']
            parsed_cats = []
            for category in all_cats:
                if category.lower() == 'placeholders':
                    parsed_cats.append(self.orange_text + category.capitalize() + self.color_end)
                elif category.lower() in self.blacklisted:
                    parsed_cats.append(self.red_text + category.capitalize() + self.color_end)
                else:
                    parsed_cats.append(category.capitalize())
            parsed_cats = list(set(parsed_cats))

            dns_records = lab_results[domain]['dns']
            if not dns_records:
                dns_records = ['NO RESULTS']

            click.secho('|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|'.format(
                        domain, health, health_dns, ', '.join(dns_records), whois,
                        creation, expiration, ', '.join(parsed_cats), ', '.join(xforce),
                        ', '.join(talos), ', '.join(bluecoat), ', '.join(fortiguard),
                        ', '.join(opendns), ', '.join(trendmicro), ', '.join(mxtoolbox)),
                        fg='yellow')

    def generate_monitor_message(self, lab_results, slack):
        """Accepts the results of check_domain_status() and generate a Slack messages for any
        burned domains.
        """
        for domain in lab_results:
            message = ''
            health = lab_results[domain]['health']
            if not health == 'Healthy':
                message = message + 'Uh oh, *{}* has been flagged and should now be considered BURNED.'.format(domain)
            bad_cats = []
            all_cats = lab_results[domain]['categories']['all']
            for category in all_cats:
                if category.lower() in self.blacklisted:
                    bad_cats.append(category.capitalize())
            if bad_cats:
                message = message + '*{}* has been tagged with a bad category: *{}*'.format(domain, ', '.join(bad_cats))
            # If there is a message to print, send the alert to the user's terminal
            if not message == '':
                click.secho(message, fg='red')
            # If Slack is configured and the user enables Slack, send a WebHook message
            if slack and self.slack_capable:
                if not message == '':
                    message = self.slack_alert_target + ' ' + message
                    slack_data = {
                                  'text': message,
                                  'username': self.slack_username,
                                  'icon_emoji': self.slack_emoji,
                                  'channel': self.slack_channel
                                }
                    response = requests.post(self.slack_webhook_url, data=json.dumps(slack_data), headers={'Content-Type': 'application/json'})
                    if response.status_code != 200:
                        click.secho('[!] Request to slack returned an error %s, the response is:\n%s' % (response.status_code, response.text), fg='red')
