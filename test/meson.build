gtest_dep = dependency('gtest', required:false)
gmock_dep = dependency('gmock', required: false)
phosphor_logging_dep = dependency('phosphor-logging',required: false)

if not gtest_dep.found()
    gtest_subproject = cmake.subproject('gtest')
    cm_gtest = gtest_subproject.dependency('gtest')
    cm_gtest_main = gtest_subproject.dependency('gtest_main')
    cm_gmock = gtest_subproject.dependency('gmock')
    cm_gmock_main = gtest_subproject.dependency('gmock_main')
    threads = dependency('threads')
    boost_dep = dependency('boost')
    systemd_dep = dependency('systemd')
    phosphor_logging_dep = dependency('phosphor-logging')
    gtest_dep = declare_dependency(dependencies: [cm_gtest,
            cm_gtest_main, threads])
    gmocktest_dep = declare_dependency(dependencies: [cm_gmock,
    cm_gmock_main, threads])
endif

common_test_deps = [
    gtest_dep,
    phosphor_logging_dep,
    gmock_dep,
    sdbusplus_partial_dep,
    boost_partial_dep,
]

inc_dir = include_directories('../hw/aspeed/', '../include/')

test_i3c_hub_src = [
    '../hw/aspeed/i3c_utils.cpp',
    '../src/i3c_hub_detector.cpp',
    '../src/hub_configuration.cpp',
    'test_utils.cpp'
]

i3chub = executable(
    'test_i3chub_detector',
    test_i3c_hub_src,
    include_directories : inc_dir,
    dependencies: common_test_deps,
    cpp_args : '-DUNIT_TESTS'
)

test('I3C Hub test', i3chub, is_parallel : false)
