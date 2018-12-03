#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This script uses the DomainReview class to first pull a list of domains registered under the
provided Namecheap account. Each domain is then reviewed to ensure it is ready to be used for an
op. This involves checking to see if Whois Guard is enabled, the domain is not expired, the domain
is properly categorized, the domain has not been flagged in VirusTotal or tagged with a bad
category, and the domain is not blacklisted for spam.

DomainReview checks the domain against VirusTotal, Cisco Talos, Bluecoat, IBM X-Force, Fortiguard, 
and MXToolbox.
"""


from time import sleep

import click

from lib import review, helpers


# Setup a class for CLICK
class AliasedGroup(click.Group):
    """Allows commands to be called by their first unique character."""

    def get_command(self, ctx, cmd_name):
        """
        Allows commands to be called by their first unique character
            :param ctx: Context information from click
            :param cmd_name: Calling command name
            :return:
        """
        command = click.Group.get_command(self, ctx, cmd_name)
        if command is not None:
            return command
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail("Too many matches: %s" % ", ".join(sorted(matches)))

# That's right, we support -h and --help! Not using -h for an argument like 'host'! ;D
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=200)
@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)

# Note: The following function descriptors will look weird and some will contain '\n' in spots.
# This is necessary for CLICK. These are displayed with the help info and need to be written
# just like we want them to be displayed in the user's terminal. Whitespace really matters.

def domaincheck():
    """
Welcome to DomainCheck! To use this tool, select a module you wish to run. Functions are split into
modules to support check and monitor modes.

Run 'domaincheck.py <MODULE> --help' for more information on a specific mode.
    """
    # Everything starts here
    pass

@domaincheck.command(name='checkup', short_help='Collects all Namecheap domains and then performs \
a health checkup.')
@click.option('-f', '--filter-list', help='A comma-separated list of domains to review instead of all \
Namecheap domains. The provided domain names will only be checked if they are owned by the \
Namecheap account being used.', required=False)
@click.option('--wiki', is_flag=True, help='Enable this flag to output the results in \
Confluence-compatible markup language for pasting into a wiki page.', required=False)
# Pass the above arguments on to your verify function
@click.pass_context

def checkup(self, filter_list, wiki):
    """
Collect all domain names under the Namecheap account and perform a health checkup on all of them.
    """
    if filter_list:
        filter_list = filter_list.split(", ")
        click.secho("[+] Filtering domain list to only check:\n{}".format("\t\n".join(filter_list)), fg='green')
    # Get the list of domains and review each one
    domain_review = review.DomainReview()
    domains_list = domain_review.get_domain_list()
    lab_results = domain_review.check_domain_status(domains_list, filter_list)
    domain_review.output_csv(lab_results)
    # Print the table for Confluence updates
    if wiki:
        domain_review.print_confluence_table(lab_results)

@domaincheck.command(name='monitor', short_help="Monitors the provided list of domain names for \
changes in categorization or status.")
@click.option('-d', '--domains', help="A comma-separated list of domains to monitor. The provided \
domain names will only be checked if they are owned by the Namecheap account being used.", required=True)
@click.option('-i', '--interval', type=int, help="How long (in minutes) to wait between health checkups.", required=True)
@click.option('--slack', is_flag=True, help="Enable this flag to send Slack notifications instead \
of messages in the terminal. This requires the Slack config section to be completed in your \
domaincheck.config file.", required=True)
# Pass the above arguments on to your verify function
@click.pass_context

def monitor(self, filter_list, interval, slack):
    """
Monitor the provided list of domain names for changes in categorization.
    """
    filter_list = domains.split(", ")
    domain_review = review.DomainReview()
    domains_list = domain_review.get_domain_list()
    click.secho('[+] Starting monitor mode with checkups every {} minutes. Here we go!'.format(interval))
    while True:
        lab_results = domain_review.check_domain_status(domains_list, filter_list)
        domain_review.generate_monitor_message(lab_results, slack)
        print("[+] Sleeping for {} minutes...".format(interval))
        sleep(round(interval/60, 2))

if __name__ == "__main__":
    domaincheck()
