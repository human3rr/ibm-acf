project('ce-login',
        'cpp',
         version : '1.0.0',
         default_options : 'default_library=static'
         )

#dependencies
cxx = meson.get_compiler('cpp')
#Intended to be configured if this does not match your openssl include loc
#Should not be required if package config is found for openssl though
openssl_include_dir = '/usr/include/openssl'
#Create a symbolic link in cwd to libcrypto/libssl directories to build
#if pkgconfig and find_library calls fail
cwd = meson.current_source_dir()

libcrypto = dependency('libcrypto', required : false)
if not libcrypto.found()
  libcrypto = cxx.find_library('crypto', required : false )
  if not libcrypto.found()
    #Last resort to build with libcrypto
    crypto_inc = include_directories ( openssl_include_dir )
    libcrypto = declare_dependency( link_args : [ '-L' + cwd, '-lcrypto' ], include_directories : crypto_inc )
  endif
endif

libssl = dependency('libssl', required : false)
if not libssl.found()
  libssl = cxx.find_library('ssl', required : false)
  if not libssl.found()
    #Last resort to build with libssl
    crypto_inc = include_directories ( openssl_include_dir )
    libssl = declare_dependency( link_args : [ '-L',  '-lssl' ], include_directories : crypto_inc )
  endif
endif

#Fetches jsmn header library
jsmn = dependency('jsmn', required : true, fallback : ['jsmn', 'jsmn_dep'])
lib_deps = [ libcrypto, libssl, jsmn ]

#includes
inc_dir = include_directories(['celogin/include', './cli', 'celogin/src' ])

#sources
ce_login_sources = ['celogin/src/CeLoginAsnV1.cpp',
                    'celogin/src/CeLogin.cpp',
                    'celogin/src/CeLoginJson.cpp',
                    'celogin/src/CeLoginJsonExterns.cpp',
                    'celogin/src/CeLoginUtil.cpp',
                    'celogin/src/JsmnUtils.cpp',
                    'celogin/src/Jsmn.cpp',
                    'celogin/src/CeLoginAsnV1.cpp',
                    ]

cli_sources = [ 'cli/CliCeLoginV1.cpp',
                'cli/CliCreateHsf.cpp',
                'cli/CliDecodeHsf.cpp',
                'cli/CliUtils.cpp',
                'cli/CliVerifyHsf.cpp',
                'cli/main.cpp',
                ]

all_srcs = ce_login_sources + cli_sources

#compiler arguments
args = ['-O2', '-DMFG_IBMI_TARGET']

#library target
if get_option('lib')
  ce_login_lib = library('celogin', cpp_args : args, pic : true, sources : ce_login_sources, dependencies : lib_deps, include_directories : inc_dir, install : true)
  #dependency definition for export to other projects
  lib_ce_login_dep = declare_dependency( dependencies : lib_deps, include_directories : inc_dir, link_with : ce_login_lib)
  install_headers('celogin/include/CeLogin.h', 'celogin/src/CeLoginAsnV1.h', 'celogin/src/CeLoginUtil.h', 'celogin/src/JsmnUtils.h', 'celogin/src/CeLoginJson.h')
endif

#Ce-login utility for generating access control files
if get_option('bin')

  privkey = configure_file(input : 'p10-celogin-lab-pkey.der',
               output : 'p10-celogin-lab-pkey.der',
               copy: true)

  pubkey = configure_file(input : 'p10-celogin-lab-pub.der',
               output : 'p10-celogin-lab-pub.der',
               copy: true)

  #Need jsonc for celogin_cli
  jsonc = dependency('json-c', required : false)
  if not libssl.found()
    cxx.find_library('json-c', required : true)
  endif
  cli_deps = [ lib_deps, jsonc ]

  exe = executable('celogin_cli', cpp_args : args, sources : all_srcs, dependencies : cli_deps, include_directories : inc_dir)

#Tests to run against celogin_cli creating ACF, validating, and decoding.
#Priority is set for ordering of commands as some tests depend on each other,
#eg the ACF should be created before validating it.
#If priority is not defined then it is implicitly 0
#and higher numbers are executed first

  test('Generate ACF', exe, priority : 3, args : [ 'create',
                                                   '--machine', 'P10,dev,UNSET',
                                                   '--sourceFileName', 'none',
                                                   '--password', '0penBmc',
                                                   '--expirationDate', '2025-12-25',
                                                   '--requestId', '1234',
                                                   '--pkey', privkey ,
                                                   '--output', './service.acf' ])

  test('Verify ACF', exe, priority : 2, args : [ 'verify',
                                                 '--hsfFile', './service.acf',
                                                 '--publicKeyFile', pubkey,
                                                 '--password', '0penBmc',
                                                 '--serialNumber', 'UNSET' ] )

  test('Decode ACF', exe, priority : 1, args : [ 'decode',
                                                 '--hsfFile', './service.acf',
                                                 '--publicKeyFile', pubkey])

  test('Execute celogin_cli with no args', exe, should_fail : true)

  test('Generate ACF - Malformed param', exe, priority : -100, should_fail : true,
                                          args : [ 'create',
                                                   '--machine', 'P10,dev,UNSET',
                                                   '--sourceFileName', 'none',
                                                   '--passwordBadArgument', '0penBmc',
                                                   '--expirationDate', '2025-12-25',
                                                   '--requestId', '1234',
                                                   '--pkey', privkey,
                                                   '--output', './service.acf' ] )

  test('Verify ACF - Incorrect Password', exe, priority : 1, should_fail : true,
                                          args : [ 'verify',
                                                   '--hsfFile', 'service.acf',
                                                   '--publicKeyFile', pubkey,
                                                   '--password', 'notthepassword',
                                                   '--serialNumber', 'UNSET' ] )

  test('Verify ACF - Incorrect Serial Number', exe, priority : 1, should_fail : true,
                                          args : [ 'verify',
                                                   '--hsfFile', 'service.acf',
                                                   '--publicKeyFile', pubkey,
                                                   '--password', 'notthepassword',
                                                   '--serialNumber', '123123' ] )

  test('Decode ACF - No pubkey', exe, should_fail : true,
                                          args : [ 'decode',
                                                   '--hsfFile', './service.acf',
                                                   '--publicKeyFile', 'celogin_cli'])
endif
