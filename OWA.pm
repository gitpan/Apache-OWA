package Apache::OWA;

use strict;
use vars qw($VERSION %owa_mapping %owa_version);
$Apache::OWA::VERSION = '0.4';

use DBI;
use Apache::Constants qw(:common);
use Apache::Request ();
my ($dbinfo, $sth, $sql, $r, $dbh);

# this handler may be called as PerlAuthHandler or PerlHandler
# is this a good idea? i don't know... seems convenient to me.
###################################################################
sub handler {
  $r = shift;
  $r = Apache::Request->new($r,DISABLE_UPLOADS => 1);
  # if auth required, do auth_handler, else content_handler
  ( $r->auth_type() eq "Basic") ?
    &auth_handler :
      &content_handler;
}

####################################################################
sub auth_handler {
  my ($sent_pw, $user, $db);

  # get username & password
  (my $res, $sent_pw) = $r->get_basic_auth_pw;
  return $res if $res != OK;
  $user = $r->connection->user;

  # need both username & password
  unless ( $user && $sent_pw) {
    $r->note_basic_auth_failure;
    return AUTH_REQUIRED;
  }

  # get configuration
  if ($r->dir_config('DB_AUTH')) {
    $r->dir_config('DB') ? $db =  $r->dir_config('DB') : $db = $ENV{'ORACLE_SID'};
    $dbinfo = "$user/$sent_pw\@$db";
  }
  elsif  ( $r->dir_config('DB_PROC_AUTH') ) {
    $dbinfo = $r->dir_config('DAD');
  }

  # don't authenticate sub-requests
  if ( $r->is_main() ) {

    if ( $r->dir_config('DB_AUTH') ) {
      $dbh = DBI->connect("dbi:Oracle:", $dbinfo) || return AUTH_REQUIRED;
    }

    elsif ( $r->dir_config('DB_PROC_AUTH') ) {
      my ( $proc ) = $r->dir_config('DB_PROC_AUTH');
      $dbh = DBI->connect("dbi:Oracle:", $dbinfo) || return SERVER_ERROR;

      my $rv;
      $sql = "begin :rv := $proc (:user, :pw); end;";
      $sth = $dbh->prepare($sql);
      $sth->bind_param(":user",  $user);
      $sth->bind_param(":pw",  $sent_pw);
      $sth->bind_param_inout(":rv",  \$rv, 2);
      $sth->execute || return SERVER_ERROR ;
      $sth->finish;
      $dbh->disconnect;
      return AUTH_REQUIRED if $rv != 0;
    }
  }

  # pass handling to the content handler
  $r->handler("perl-script");
  $r->push_handlers(PerlHandler=>\&content_handler );
  return OK;
}


#####################################################
sub content_handler {

  if ( $r->dir_config('DAD')) {
    ( $dbinfo ) = $r->dir_config('DAD');
  }
  $dbinfo || die "Apache::OWA error: you must provide either DAD or PerlAuthHandler Apache::OWA configuration\n";

  $dbh = DBI->connect("dbi:Oracle:", $dbinfo)    || &error1($DBI::errstr);

  # map uri to plsql precedure name
  my @plsql = reverse( split (/\//, $r->uri() ));
  my $plsql = shift(@plsql);

  if ( $r->dir_config('SCHEMA') ) {
    $plsql = $r->dir_config('SCHEMA') .".". $plsql;
  }
  else {
    $plsql =  shift(@plsql)  .".".  $plsql ;
  }

  # uppercase all procedure names. oracle doesn't care, but perl does.
  $plsql =~ tr/a-z/A-Z/;
  $owa_mapping{$r->uri()} = $plsql;

  $sql = "BEGIN dbms_session.reset_package; :version := owa.initialize; END;";
  $sth = $dbh->prepare($sql);
  $sth->bind_param_inout(":version", \$owa_version{$r->uri()}, 1);
  $sth->execute    || &error2($DBI::errstr, $sql);
  $sth->finish;

  $sql = "
  DECLARE var_val  owa.vc_arr;
          var_name owa.vc_arr;
  BEGIN
    owa.ip_address(1):= ?;
    owa.ip_address(2):= ?;
    owa.ip_address(3):= ?;
    owa.ip_address(4):= ?;
--    owa.user_id:= NULL;
--    owa.password:= NULL;
    owa.hostname:=?;
    var_val(1):=?;   var_name(1):='REQUEST_METHOD';
    var_val(2):=?;   var_name(2):='PATH_INFO';
    var_val(3):=?;   var_name(3):='PATH_TRANSLATED';
    var_val(4):=?;   var_name(4):='QUERY_STRING';
    var_val(5):=?;   var_name(5):='REMOTE_USER';
    var_val(6):=?;   var_name(6):='AUTH_TYPE';
    var_val(7):=?;   var_name(7):='SCRIPT_NAME';
    var_val(8):=?;   var_name(8):='SERVER_SOFTWARE';
    var_val(9):=?;   var_name(9):='CONTENT_LENGTH';
    var_val(10):=?;  var_name(10):='CONTENT_TYPE';
    var_val(11):=?;  var_name(11):='SERVER_PROTOCOL';
    var_val(12):=?;  var_name(12):='SERVER_NAME';
    var_val(13):=?;  var_name(13):='SERVER_PORT';
    var_val(14):=?;  var_name(14):='REMOTE_ADDR';
    var_val(15):=?;  var_name(15):='REMOTE_HOST';
    var_val(16):=?;  var_name(16):='HTTP_USER_AGENT';
";

  my ($ip1,$ip2,$ip3,$ip4) = split(/./,  $r->subprocess_env('REMOTE_ADDR'));

  my @bind_vars = ( $ip1,$ip2,$ip3,$ip4,$r->subprocess_env('SERVER_NAME'),
                    $r->subprocess_env('REQUEST_METHOD'),
                    $r->uri(),
                    $r->subprocess_env('SCRIPT_FILENAME'),
                    $r->subprocess_env('QUERY_STRING'),
                    $r->subprocess_env('REMOTE_USER'),
                    $r->subprocess_env('AUTH_TYPE'),
                    $r->subprocess_env('SCRIPT_NAME'),
                    $r->subprocess_env('SERVER_SOFTWARE'),
                    $r->subprocess_env('CONTENT_LENGTH'),
                    $r->subprocess_env('CONTENT_TYPE'),
                    $r->subprocess_env('SERVER_PROTOCOL') ,
                    $r->subprocess_env('SERVER_NAME') ,
                    $r->subprocess_env('SERVER_PORT') ,
                    $r->subprocess_env('REMOTE_ADDR') ,
                    $r->subprocess_env('REMOTE_HOST') ,
                    $r->subprocess_env('HTTP_USER_AGENT') );

  if ( $r->subprocess_env('HTTP_COOKIE') ) {
    $sql .= " var_val(17):=?; var_name(17):='HTTP_COOKIE'; owa.init_cgi_env(17,var_name,var_val); END;";
    push @bind_vars, ( $r->subprocess_env('HTTP_COOKIE') );
  }

  else {
    $sql .= " owa.init_cgi_env(16,var_name,var_val); END;";
  }

  $sth = $dbh->prepare($sql);
  my $rv = $sth->execute(@bind_vars)    || &error2($DBI::errstr, $sql);
  $sth->finish;

# get auth_mode. don't know what to do with it, so i commented it out
#
#  $sql ="BEGIN :auth_scheme :=  owa.auth_scheme; END;";
#  $sth = $dbh->prepare($sql);
#  $sth->bind_param_inout(":auth_scheme", \$auth_scheme, 2);
#  $sth->execute;
#  $sth->finish;

# get protection_realm. don't know what to do with it, so i commented it out
#
#  $sql = "BEGIN :protection_realm := owa.protection_realm; END;";
#  $sth = $dbh->prepare($sql);
#  $protection_realm;
#  $sth->bind_param_inout(":protection_realm", \$protection_realm, 10);
#  $sth->execute
#      || &error2($DBI::errstr, $sql);
#  $sth->finish;



  # check for arguments
  my @names =  $r->param();
  if ( scalar @names ) {
    my ($declares, $defines, $args);

    # put arguments in place
    foreach my $name ( @names ) {
      $declares .= "$name varchar2(4096);\n";
      $defines .= "$name := '" . $r->param($name) . "';\n";
      $args .= "," if ($args);
      $args .= "$name=>$name";
    }
    $sql = "DECLARE $declares BEGIN $defines $plsql ($args); END;";
  }

  # no arguments
  else {
    $sql = "DECLARE BEGIN $plsql; END;";
  }
  #print STDERR "$sql\n";
  $sth = $dbh->prepare($sql);
  $sth->execute || &error2($DBI::errstr, $sql);
  $sth->finish;

  my $content;
  my $pos = 1;
  my $rows = 0;

# need to handle version <= 3 and 4 differently...
# version is returned from owa.initialize as 256*major_version + minor_version
# version 3 and earlier:

  if ($owa_version{$r->uri()} <= 768) {
    $sql ="begin
     :content := NULL;
     :rows := htp.htbuf.count;
     for i in 1 .. htp.htbuf.count  loop
           :content := :content || htp.htbuf(:pos);
           :pos := :pos + 1;
           if i > 126 then
               exit;
           end if;
           if ( :pos >= htp.htbuf.count )  then
               :pos := 0 ;
               exit;
           end if;
    end loop;
END;";

    $sth = $dbh->prepare($sql);
    $sth->bind_param_inout(":rows", \$rows, 1);
    $sth->bind_param_inout(":pos", \$pos, 1);
    $sth->bind_param_inout(":content", \$content, { TYPE => 24 } );
    my $numgets = 0;

    while ( $pos > 0) {
      $rv = $sth->execute      || &error2($DBI::errstr,$sql);
      $numgets++;

      #put Content-type in there if needed, but only first time.
      $content = "Content-type: text/html\n\n" . $content
        unless ( $content =~ /^Location|^Status|^Set-Cookie|^Content\-type/i || $numgets > 1) ;
      $r->print($content);
      #print STDERR "$content pos: $pos rows: $rows numgets: $numgets version: $owa_version rv: $rv\n";
    }
  }

# version 4:
  elsif ($owa_version{$r->uri()} == 1024){
    $sql ="begin
     :content := NULL;
     :rows := 0;
     while ( :pos > 0 AND  :rows < 127 ) loop
       :content := :content || htp.get_line(:pos);
       :rows := :rows + 1;
     end loop;
END;";

    $sth = $dbh->prepare($sql);
    $sth->bind_param_inout(":rows", \$rows, 1);
    $sth->bind_param_inout(":content", \$content, { TYPE => 24 } );  # varchar2
    $sth->bind_param_inout(":pos", \$pos, 1);
    my $numgets = 0;
    while ( $pos > 0) {
      $rv = $sth->execute      || &error2($DBI::errstr,$sql);
      $numgets++;

      #put Content-type in there if needed, but only first time.
      $content = "Content-type: text/html\n\n" . $content
        unless ( $content =~ /^Location|^Status|^Set-Cookie|^Content\-type/i || $numgets > 1) ;
      $r->print($content);
      #print STDERR "$content pos: $pos rows: $rows numgets: $numgets version: $owa_version rv: $rv\n";
    }
  }
  else { error1("unknown owa_version!"); }

  $sth->finish;
  $dbh->disconnect;
}
##################################################################
sub error1 {
  my ($errstr) = shift;
  $r->print("Content-type: text/html\n\n",
    "Oracle error: <br>",
    "<pre>", $errstr, "</pre><hr>");
  $dbh->disconnect;
  die;
}
#################################################################
sub error2 {
  my ($errstr, $sql) = @_;
  $r->print("Content-type: text/html\n\n",
    "Oracle error:<br>",
    "<pre>", $errstr, "</pre><br>",
    "while executing:<br>",
    "<pre>", $sql, "</pre><br>");
  $dbh->disconnect;
  die;
}
#################################################################
Apache::Status->menu_item('OWA' => "OWA info",
                          sub {
                            my($r,$q) = @_;
                            my(@strings);
                            unless (scalar  %Apache::OWA::owa_version) {
                              push @strings , "No information available";
                            }
                            else {
                              push @strings, "<table border=1><tr><td align=right><b>URI</b></td>";
                              push @strings, "<td align=right><b>PL/SQL Procedure</b></td>";
                              push @strings, "<td align=right><b>PL/SQL Web Toolkit version</b></td></th>";
                              foreach my $key (keys %Apache::OWA::owa_version) {
                                push @strings,  "<tr><td align=right>$key</td>";
                                push @strings,  "<td align=right>$Apache::OWA::owa_mapping{$key}</td>";
                                push @strings,  "<td align=right>", $Apache::OWA::owa_version{$key}/256, "</td></tr>";
                              }
                              push @strings, "</table>";
                            }
                            return \@strings;
                          }
                         ) if Apache->module('Apache::Status');


1;
__END__


=head1 NAME

Apache::OWA - Run OWA PL/SQL apllications

=head1 SYNOPSIS

<Location /scott/*>
  SetHandler perl-script
  PerlHandler Apache::OWA;
  PerlSetVar DAD scott/tiger@oracle
</Location>

(Most of the documentation is in the README)

=head1 DESCRIPTION

Apache::OWA makes it possible to run scripts written using Oracle's PL/SQL
Web Toolkit under Apache.

=head1 AUTHOR

Svante Sörmark, svinto@ita.chalmers.se.
Latest version available from http://www.ita.chalmers.se/~svinto/apache

=head1 COPYRIGHT

The Apache::OWS module is free software; you can redistribute it and/or 
modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<Apache>, L<mod_perl>, L<DBI>, L<DBD::Oracle>, L<Apache::DBI>


=cut
