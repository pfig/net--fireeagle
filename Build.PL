use strict;
use Module::Build;

my $build = Module::Build
  ->new( module_name  => "Net::FireEagle",
         license      => 'perl',
         script_files => [ ],
         requires     => {
                          'LWP::UserAgent'           => '0',
                          'CGI'                      => '0',
                          'Class::Data::Inheritable' => '0',
                          'Class::Accessor'          => '0',
                          'Test::More'               => '0',
                          'Net::OAuth::Request'      => '0.06',
                        },
         create_makefile_pl => 'traditional',
       );

$build->create_build_script;

