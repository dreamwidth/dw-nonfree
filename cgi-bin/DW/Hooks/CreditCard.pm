#!/usr/bin/perl
#
# DW::Hooks::CreditCard
#
# This file contains the hooks used to show DW-specific FAQs and comms
# on community/index.bml.
#
# Authors:
#      Denise Paolucci <denise@dreamwidth.org>
#
# Copyright (c) 2013 by Dreamwidth Studios, LLC.
#
# This program is NOT free software or open-source; you can use it as an
# example of how to implement your own site-specific extensions to the
# Dreamwidth Studios open-source code, but you cannot use it on your site
# or redistribute it, with or without modifications.

package DW::Hooks::CreditCard;

use strict;
use LJ::Hooks;

# returns: message about having credit card charge permission +
# info on what the charge will look like on your statement.
LJ::Hooks::register_hook( 'cc_charge_from', sub {

    my $ret;

    $ret = "<p>" . BML::ml( 'shop.cc.charge.from' ) . "</p>";

    return $ret;
} );