project(
    'dtnc',
    'c',
    version: '0.1.0',
    default_options: ['c_std=c17', 'warning_level=3'],
)

cc = meson.get_compiler('c')

if get_option('broad_warnings')
    if cc.get_id() == 'gcc'
        add_project_arguments('-Wshadow', language: 'c')
    elif cc.get_id() == 'clang'
        add_project_arguments('-Wshadow-all', language: 'c')
    endif
    add_project_arguments(
        '-Wpointer-arith',
        '-Wcast-qual',
        '-Wcast-align',
        '-Wstrict-prototypes',
        '-Wmissing-prototypes',
        '-Wconversion',
        language: 'c',
    )
endif

add_project_arguments('-D_POSIX_C_SOURCE=202405L', language: 'c')

conf_data = configuration_data(
    {
        'HAVE_ARC4RANDOM': cc.has_function(
            'arc4random',
            prefix: '#include <stdlib.h>',
        ),
        'HAVE_ARC4RANDOM_BUF': cc.has_function(
            'arc4random_buf',
            prefix: '#include <stdlib.h>',
        ),
        'HAVE_ARC4RANDOM_UNIFORM': cc.has_function(
            'arc4random_uniform',
            prefix: '#include <stdlib.h>',
        ),
        'HAVE_ERR_H': cc.has_header('err.h'),
        'HAVE_EXPLICIT_BZERO': cc.has_function(
            'explicit_bzero',
            prefix: '#include <strings.h>',
        ),
        'HAVE_GETENTROPY': cc.has_function(
            'getentropy',
            prefix: '#include <unistd.h>',
        ),
        'HAVE_GETRANDOM': cc.has_function(
            'getrandom',
            prefix: '#include <sys/random.h>',
        ),
        'HAVE_MMAP': cc.has_function('mmap', prefix: '#include <sys/mman.h>'),
        'HAVE_STRTONUM': cc.has_function(
            'strtonum',
            prefix: '#include <stdlib.h>',
        ),
        'HAVE_SYS_MMAN_H': cc.has_header('sys/mman.h'),
        'HAVE_SYS_RANDOM_H': cc.has_header('sys/random.h'),
        'HAVE_SYS_QUEUE_H': cc.has_header('sys/queue.h'),
    },
)

errc_functions = [
    'vwarn',
    'vwarnc',
    'vwarnx',
    'verr',
    'verrc',
    'verrx',
    'err',
    'errc',
    'errx',
    'warn',
    'warnc',
    'warnx',
]

foreach f : errc_functions
    conf_data.set(
        'HAVE_' + f.to_upper(),
        cc.has_function(f, prefix: '#include <err.h>'),
    )
endforeach

# Taken from OpenSSH's Autoconf check for __progname
progname_check_code = '''#include <stdio.h>
int main(void) {
  extern char *__progname;
  printf("%s", __progname);
  return 0;
}
'''
conf_data.set(
    'HAVE___PROGNAME',
    cc.links(progname_check_code, name: '__progname check'),
)

configure_file(output: 'config-compat.h', configuration: conf_data)
cinc = include_directories('.', 'compat')

ion_dep = dependency('ion')

deps = [ion_dep]

subdir('compat')
