use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'	=> 'Apache::AuthenPasswd',
    'VERSION_FROM' => 'AuthenPasswd.pm', # finds $VERSION
    'dist' => {COMPRESS => 'gzip', SUFFIX => 'gz'}
);
