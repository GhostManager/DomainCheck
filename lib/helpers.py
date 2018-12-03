#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper functions for custom libraries.
"""


import configparser

import click


try:
    CONFIG_PARSER = configparser.ConfigParser()
    CONFIG_PARSER.read("domaincheck.config")
except configparser.Error as error:
    click.secho('[!] Could not open the domaincheck.config file. Make sure it is readable.', fg='red')
    click.secho('L.. Details: {}'.format(error), fg='red')
    exit()

def config_section_map(section):
    """This function helps by reading a config file section and returning a dictionary object 
    that can be referenced for configuration settings.

    Parameters:
    section     The section of the config file to be collected
    """
    try:
        section_dict = {}
        # Parse the config file's sections into options
        options = CONFIG_PARSER.options(section)
        # Loop through each option
        for option in options:
            # Get the section and option and add it to the dictionary
            section_dict[option] = CONFIG_PARSER.get(section, option)
            if section_dict[option] == -1:
                click.secho('[*] Skipping: {}'.format(option), fg='yellow')
        # Return the dictionary of settings and values
        return section_dict
    except configparser.Error as error:
        click.secho('[!] There was an error with: {}'.format(section), fg='red')
        click.secho('L.. Details: {}'.format(error), fg='red')
