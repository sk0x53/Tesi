use File::Basename qw(fileparse);

add_cus_dep('acn', 'acr', 0, 'makeglossaries');

sub makeglossaries {
    my ($base_name, $path) = fileparse($_[0]);
    system("makeglossaries", "-d", $path, $base_name);
}