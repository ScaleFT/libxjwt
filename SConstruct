#!/usr/bin/env scons
#
#  Copyright 2017, ScaleFT Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import SCons
import os, subprocess, platform
from site_scons.utils import get_files, InstallHeader
from os.path import join as pjoin

from SCons.Script.SConscript import SConsEnvironment

SConsEnvironment.Chmod = SCons.Action.ActionFactory(os.chmod,
        lambda dest, mode: 'Chmod("%s", 0%o)' % (dest, mode))

# Ubuntu LTS 14.04 Trusty includes SCons 2.3.0, so thats our minimum bar for now.
EnsureSConsVersion(2, 3, 0)

xjwt_version = "1.0.0"
platform_name = platform.system().upper()

opts = Variables(['build.py', 'build-%s.py' % (platform_name.lower())])

available_profiles = ['debug', 'release']
available_build_types = ['static','shared']

opts.Add(EnumVariable('profile', 'build profile', 'release', available_profiles, {}, True))
opts.Add(EnumVariable('build_type', 'build profile', 'shared', available_build_types, {}, True))
opts.Add(PathVariable('destdir',
                      'DESTDIR to prefix path', "/"))
opts.Add(PathVariable('prefix',
                      'Path to Install', "/usr/local"))
opts.Add(PathVariable('with_jansson',
                      'Prefix to Jansson installation', None))
opts.Add(PathVariable('with_openssl',
                      'Prefix to OpenSSL installation', None))

env = Environment(options=opts,
                  ENV = os.environ.copy(),
                  tools=['default'])

conf = Configure(env, custom_tests = {})

# clang-analyzer support
conf.env["CC"] = os.getenv("CC") or env["CC"]
conf.env["CXX"] = os.getenv("CXX") or env["CXX"]
conf.env["ENV"].update(x for x in os.environ.items() if x[0].startswith("CCC_"))

if not conf.CheckCC():
  print 'Unable to find a functioning compiler, tried %s' % (conf.env.get('CC'))
  Exit(-1)

if conf.env.get('with_jansson'):
    conf.env.AppendUnique(LIBPATH=["${with_jansson}/lib"])
    conf.env.AppendUnique(CPPPATH=["${with_jansson}/include"])

if not conf.CheckLibWithHeader('jansson', 'jansson.h', 'c'):
    print 'Unable to use Jansson development enviroment: with_jansson=%s' %  conf.env.get('with_jansson')
    Exit(1)

if conf.env.get('with_openssl'):
    conf.env.AppendUnique(LIBPATH=["${with_openssl}/lib"])
    conf.env.AppendUnique(CPPPATH=["${with_openssl}/include"])

if not conf.CheckLibWithHeader('libssl', 'openssl/ssl.h', 'C', 'SSL_library_init();', True):
    print 'Unable to use OpenSSL development enviroment: with_openssl=%s' %  conf.env.get('with_openssl')
    Exit(1)

if not conf.CheckLibWithHeader('libcrypto', 'openssl/err.h', 'C', 'ERR_load_crypto_strings();', True):
    print 'Unable to use OpenSSL development enviroment (missing libcrypto?): with_openssl=%s' %  conf.env.get('with_openssl')
    Exit(1)


for flag in ['-pedantic', '-std=gnu89', '-Wno-variadic-macros', '-Wno-deprecated-declarations']:
  conf.env.AppendUnique(CCFLAGS=flag)
  if not conf.CheckCC():
    print 'Checking for compiler support of %s ... no' % flag
    conf.env['CCFLAGS'] = filter(lambda x: x != flag, conf.env['CCFLAGS'])
  else:
    print 'Checking for compiler support of %s ... yes' % flag

env = conf.Finish()

selected_variant = '%s-%s' % (env['profile'].lower(), env['build_type'].lower())
print "Selected %s variant build..." % (selected_variant)

variants = []

bt = [env['build_type'].upper()]
for profile in available_profiles:
    for build in available_build_types:
        variants.append({'PROFILE': profile.upper(), 'BUILD': build.upper(), 'PLATFORM': platform_name})

rootenv = env

options = {
  'PLATFORM': {
    'DARWIN': {
      'CPPDEFINES': ['DARWIN'],
    },
    'LINUX': {
      'CPPDEFINES': ['LINUX', '_XOPEN_SOURCE', '_BSD_SOURCE'],
    },
    'FREEBSD': {
      'CPPDEFINES': ['FREEBSD'],
    },
  },
  'PROFILE': {
    'DEBUG': {
      'CCFLAGS': ['-Wall', '-O0', '-ggdb', '-Wno-long-long'],
      'CPPDEFINES': ['DEBUG'],
    },
    'RELEASE': {
      'CCFLAGS': ['-Wall', '-O2', '-Wno-long-long'],
      'CPPDEFINES': ['NODEBUG'],
    },
  },
}
append_types = ['CCFLAGS', 'CFLAGS', 'CPPDEFINES', 'LIBS', 'LINKFLAGS']
replace_types = ['CC']

all_targets = {}
all_test_targets = {}
all_install_targets = {}

so_path = pjoin(rootenv["destdir"] + rootenv["prefix"], "lib")
header_path = pjoin(rootenv["destdir"] + rootenv["prefix"], "include", "xjwt")

for vari in variants:
    targets = []
    test_targets = []
    install_targets = []

    env = rootenv.Clone()

    for k in sorted(options.keys()):
        ty = vari.get(k)
        if options[k].has_key(ty):
            for key,value in options[k][ty].iteritems():
                if key in append_types:
                    p = {key: value}
                    env.AppendUnique(**p)
                elif key in replace_types:
                    env[key] = value
                else:
                    print('Fix the SConsscript, its missing support for %s' % (key))
                    Exit(1)

    profile = vari['PROFILE']
    build = vari['BUILD']
    variant = '%s-%s' % (profile.lower(), build.lower())
    vdir = pjoin('build', variant)
    env['PROFILE'] = profile 
    env['BUILD'] = build

    lib = SConscript('SConscript', exports='env', variant_dir=pjoin(vdir, 'libxjwt'), duplicate=0)
    env['libxjwt'] = lib
    env['libxjwt_CPPPATH'] = pjoin(env.Dir('#').abspath, 'libxjwt', 'include')
    targets.append(lib)

    if variant == selected_variant and not env.GetOption('clean'):
        imod = None
        if build == "STATIC":
            imod = env.Install(so_path, source = [lib])
        else:
            imod = env.InstallVersionedLib(so_path, source = [lib], SHLIBVERSION=xjwt_version)
        install_targets.append(imod)
        headers = InstallHeader(env, header_path, get_files(env, pjoin('include', 'xjwt'), ['*.h']))
        install_targets.append(headers)

    tests = SConscript('tests/SConscript', variant_dir=pjoin(vdir, 'libxjwt-tests'), duplicate=0, exports='env')
    for t in tests[0]:
        run = env.Command(str(t) + ".testrun", t, [""+str(t)])
        env.AlwaysBuild(run)
        test_targets.append(run)

    all_targets[variant] = targets
    all_test_targets[variant] = test_targets
    all_install_targets[variant] = install_targets

fenv = env.Clone()

all_source_files = get_files(fenv, 'src', ['*.c', '*.h']) + \
                   get_files(fenv, 'tests', ['*.c', '*.h']) + \
                   get_files(fenv, pjoin('src', 'internal'), ['*.c', '*.h']) + \
                   get_files(fenv, pjoin('include', 'xjwt'), ['*.c', '*.h'])

fenv['CLANG_FORMAT'] = 'clang-format'
fenv['CLANG_FORMAT_OPTIONS'] = '-style="{BasedOnStyle: Google, SortIncludes: false}" -i'
formatit = fenv.Command('.clang-format-all-source', all_source_files,
                    '$CLANG_FORMAT $CLANG_FORMAT_OPTIONS $SOURCES')
fenv.AlwaysBuild(formatit)

env.Alias('format', formatit)

env.Alias('install', all_install_targets[selected_variant])
env.Alias('test', all_test_targets[selected_variant])

if env.GetOption('clean'):
  env.Clean(all_targets.values()[0], get_files(env, 'build', ['*.gcda', '*.gcno']))
  env.Default([all_targets.values(),
               all_test_targets.values(),
               all_install_targets.values()])
else:
  env.Default([all_targets[selected_variant]])