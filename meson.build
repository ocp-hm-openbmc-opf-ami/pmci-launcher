project(
    'pmci_launcher', ['c','cpp'],
    license: 'Apache-2.0',
    version: '0.1',
    meson_version: '>=1.1.1',
    default_options: [
        'warning_level=3',
        'werror=true',
        'cpp_std=c++23',
        'c_std=gnu11',
    ],
)

add_project_arguments(
    '-Wno-pedantic',
    language: 'cpp',
)

yocto_build = get_option('yocto_dep')
build_tests = get_option('tests')

dep_required = false
if yocto_build.enabled()
    dep_required = true
endif

incdir = include_directories('hw/aspeed',
                             'include')

boost = dependency('boost', required: dep_required, version : '>=1.79.0',
        modules: [ 'coroutine', 'context'], include_type: 'system')
if not boost.found()
    boost_proj = subproject('boost')
    boost = boost_proj.get_variable('boost_dep')
endif

boost_partial_dep = boost.partial_dependency(compile_args : false,
    link_args: true, includes : true, links: true)

systemd = dependency('systemd', required: dep_required)
systemd_system_unit_dir = systemd.get_pkgconfig_variable(
    'systemdsystemunitdir',
    define_variable: ['prefix', get_option('prefix')])

sdbusplus = dependency('sdbusplus', required : dep_required)
if not sdbusplus.found()
    sdbusplus_proj = subproject('sdbusplus')
    sdbusplus = sdbusplus_proj.get_variable('sdbusplus_dep')
endif

sdbusplus_partial_dep = sdbusplus.partial_dependency(compile_args : false,
    link_args: true, includes : true, links: true)

phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces', required: dep_required)
if not yocto_build.enabled() and build_tests.enabled()
    if not phosphor_dbus_interfaces_dep.found()
       phosphor_dbus_interfaces_proj = subproject('phosphor-dbus-interfaces')
       phosphor_dbus_interfaces_dep = phosphor_dbus_interfaces_proj.get_variable('phosphor_dbus_interfaces_dep')
    endif
endif

phosphor_logging_dep = dependency('phosphor-logging', required : dep_required)
if not phosphor_logging_dep.found()
    phosphor_dbus_interfaces_proj = subproject('phosphor-logging')
    phosphor_logging_dep = phosphor_dbus_interfaces_proj.get_variable('phosphor_logging_dep')
endif

i2c = meson.get_compiler('cpp').find_library('i2c')
if not i2c.found()
    error('i2c is required')
endif

threads = dependency('threads')

configure_file(
    copy: true,
    input: 'service_files/xyz.openbmc_project.pmci-launcher.service',
    install: true,
    install_dir: systemd_system_unit_dir,
    output: 'xyz.openbmc_project.pmci-launcher.service',
)

configure_file(
    copy: true,
    input: 'service_files/xyz.openbmc_project.I3C.Hub.Detector.service',
    install: true,
    install_dir: systemd_system_unit_dir,
    output: 'xyz.openbmc_project.I3C.Hub.Detector.service',
)

deps = [
    boost,
    threads,
    sdbusplus,
    i2c,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep
]

src_files = [
    'src/main.cpp',
]


exe_options = ['warning_level=3']
if yocto_build.enabled()
    exe_options = ['warning_level=3', 'werror=true']
endif

executable('i3c-hub-detector',
    'src/i3c_hub_detector.cpp',
    'src/hub_configuration.cpp',
    'hw/aspeed/i3c_utils.cpp',
    dependencies: deps,
    include_directories : incdir,
    install : true,
    install_dir: get_option('bindir'),
    override_options : exe_options
)

executable(
    'pmci_launcher',
    src_files,
    implicit_include_directories: false,
    dependencies: deps,
    install: true,
    install_dir: get_option('bindir'),
    override_options : exe_options
)

if build_tests.enabled() 
    subdir('test')
endif
