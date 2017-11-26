#!/bin/bash

mysql seccubus -e 'delete from finding_changes'
mysql seccubus -e 'delete from findings'
mysql seccubus -e 'delete from vulnerabilities2findings'
mysql seccubus -e 'delete from vulnerabilities'
mysql seccubus -e 'delete from inventory'
