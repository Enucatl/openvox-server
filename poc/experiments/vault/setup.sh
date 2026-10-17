#!/bin/bash
set -euo pipefail
umask 077
export KEEP_VAULT=true
exec /opt/puppetlabs/puppet/bin/ruby "$(dirname "$0")/vault-poc.rb"
