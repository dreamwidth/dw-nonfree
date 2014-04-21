#!/usr/bin/perl
#
# DW::Controller::Interface::Github
#
# Webhook that github pings when certain events happen
#
# Authors:
#      Afuna <coder.dw@afunamatata.com>
#
# Copyright (c) 2014 by Dreamwidth Studios, LLC.
#
# This program is NOT free software or open-source; you can use it as an
# example of how to implement your own site-specific extensions to the
# Dreamwidth Studios open-source code, but you cannot use it on your site
# or redistribute it, with or without modifications.

package DW::Controller::Interface::Github;

use strict;

use DW::Routing;
use LJ::JSON;
use Digest::HMAC_SHA1 ();

DW::Routing->register_string( "/interface/github", \&hooks_handler,
                                app => 1, methods => { POST => 1 } );

my %table = (
    ping            => [ \&respond_to_ping ],
    issue_comment   => [ \&label_from_comment ],
    issues          => [ \&label_from_new_issue ],
    pull_request    => [ \&label_from_new_pull_request ],
);

sub respond_to_ping {
    my $r = DW::Request->get;
    $r->print( "pinged" );
}

sub label_from_comment {
    my $payload = $_[0];

    my @labels = _extract_labels( $payload->{comment}->{body} );
    _replace_labels( $payload->{issue}->{number}, @labels );
}

sub label_from_new_issue {
    my $payload = $_[0];
    return unless $payload->{action} eq "opened";

    my $issue = $payload->{issue};

    my @labels = _extract_labels( $issue->{body} );
    _replace_labels( $issue->{number}, @labels );
}

sub label_from_new_pull_request {
    my $payload = $_[0];
    return unless $payload->{action} eq "opened";

    my $pr = $payload->{pull_request};

    my @labels = _extract_labels( $pr->{body} );
    push @labels, "is: pull request";

    _replace_labels( $pr->{number}, @labels );
}

# labels are in the form of: "##label" "##prefix:label"
sub _extract_labels {
    my ( $text ) = @_;

    my @labels_from_comment = ( $text =~ m/\#\#((?:
                                            \w      # word character
                                            |
                                            (?::[ ])  # colon followed by a space
                                        )+)
                                        /gx );
    my @valid_labels = (
            "from: suggestions", "from: support",
            "is: bug", "is: feature", "is: upkeep",
        );

    my %mapped_labels = (
        "effort: lower"     => "effort: (1) lower",
        "effort: average"   => "effort: (2) average",
        "effort: higher"    => "effort: (3) higher",

        "severity: minor"       => "severity: (1) minor",
        "severity: major"       => "severity: (2) major",
        "severity: critical"    => "severity: (3) critical",

    );
    $mapped_labels{$_} = $_ foreach @valid_labels;

    my @normalized_labels = grep { $_ }
                                map { $mapped_labels{$_} } @labels_from_comment;
    return @normalized_labels;
}

sub _replace_labels {
    my ( $issue_num, @labels ) = @_;
    return unless @labels;

    my $ua = LJ::get_useragent( role => 'github' );
    $ua->agent( $LJ::SITENAME );

    my $auth = $LJ::GITHUB{api_token} . ':x-oauth-basic';

    # replace all labels in the issue
    my $res = $ua->put( "https://${auth}\@api.github.com/repos/afuna/dw-free/issues/$issue_num/labels",
                        Content => to_json( \@labels ) );
    return $res && $res->is_success ? 1 : 0;
}

sub hooks_handler {
    my $r = DW::Request->get;
    my $body = $r->content;

    # Check received SHA1 digest if shared secret configured
    my $salt = $LJ::GITHUB{gh_signature};
    if ( defined $salt ) {
        my $received_SHA1 = $r->header_in( 'X-Hub-Signature' );
        if ( defined $received_SHA1 and $received_SHA1 =~ s/^sha1=//i ) {
            return $r->FORBIDDEN
                if lc( $received_SHA1 )
                   ne lc( Digest::HMAC_SHA1::hmac_sha1_hex( $body, $salt ) );
        } else {
            die "Missing or malformed signature header: ", $received_SHA1 // '';
        }
    }

    # parse out the payload
    my $payload = from_json( $body );

    my $hook_type = $r->header_in( 'X-GitHub-Event' );

    if ( $table{$hook_type} ) {
        foreach my $action ( @{$table{$hook_type}} ) {
                $action->( $payload );
        }
    }

    return $r->OK;
}

1;