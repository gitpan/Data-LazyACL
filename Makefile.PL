use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Data::LazyACL',
    VERSION_FROM => 'lib/Data/LazyACL.pm',
    PREREQ_PM    => {
        'Readonly'        => 0,
        'Math::BigInt'    => 0,
        'Test::Exception' => 0,
    },
);
