package Apache::AuthenPasswd;

use strict;
use Apache::Constants ':common';

$Apache::AuthenPasswd::VERSION = '0.10';

sub handler {
    my $r = shift;
    my($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if $res; #decline if not Basic

    my $name = $r->connection->user;

    if ($name eq "") {
	$r->note_basic_auth_failure;
        $r->log_reason("Apache::AuthenPasswd - no username given", $r->uri);
        return AUTH_REQUIRED;
    }

    my ($user, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell) = getpwnam $name;

    unless ($user) {
	$r->note_basic_auth_failure;
	$r->log_reason("Apache::AuthenPasswd - user $name: unknown", $r->uri);
	return AUTH_REQUIRED;
    }

    if(crypt($sent_pwd, $passwd) eq $passwd) {
	return OK;
    } else {
	$r->note_basic_auth_failure;
	$r->log_reason("Apache::AuthenPasswd - user $name: bad password", $r->uri);
	return AUTH_REQUIRED;
    }

    return OK;
}

1;

__END__

=head1 NAME

Apache::AuthenPasswd - mod_perl passwd Authentication module

=head1 SYNOPSIS

    <Directory /foo/bar>
    # This is the standard authentication stuff
    AuthName "Foo Bar Authentication"
    AuthType Basic

    PerlAuthenHandler Apache::AuthenPasswd

    # Standard require stuff, /etc/passwd users or /etc/group groups, and
    # "valid-user" all work OK
    require user username1 username2 ...
    require group groupname1 groupname2 ... # [Need Apache::AuthzPasswd]
    require valid-user

    # The following is actually only needed when authorizing
    # against /etc/group. This is a separate module.
    PerlAuthzHandler Apache::AuthzPasswd

    </Directory>

    These directives can also be used in the <Location> directive or in
    an .htaccess file.

= head1 DESCRIPTION

This perl module is designed to work with mod_perl. It is a direct
adaptation (i.e. I modified the code) of Michael Parker's
(B<parker@austx.tandem.com>) Apache::AuthenSmb module.

The module uses getpwnam to retrieve the B<passwd> entry from the
B</etc/passwd> file, using the supplied username as the search key.  It
then uses B<crypt()> to verify that the supplied password matches the
retrieved hashed password.

= head2 Apache::AuthenPasswd vs. Apache::AuthzPasswd

I've taken "authentication" to be meaningful only in terms of a user and
password combination, not group membership.  This means that you can use
Apache::AuthenPasswd with the B<require user> and B<require valid-user>
directives.  In the /etc/passwd and /etc/group context I consider B<require
group> to be an "authorization" concern.  I.e., group authorization
consists of establishing whether the already authenticated user is a member
of one of the indicated groups in the B<require group> directive.  This
process may be handled by B<Apache::AuthzPasswd>.  Admittedly, AuthzPasswd
is a misnomer, but I wanted to keep AuthenPasswd and AuthzPasswd related,
if only by name.

I welcome any feedback on this module, esp. code improvements, given
that it was written hastily, to say the least.

=head1 AUTHOR

Demetrios E. Paneras <dep@media.mit.edu>

=head1 COPYRIGHT

Copyright (c) 1998 Demetrios E. Paneras, MIT Media Laboratory.

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
