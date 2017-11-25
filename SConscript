from os.path import join as pjoin

Import('env')

lenv = env.Clone()

lenv.AppendUnique(CPPPATH = [pjoin("include")])

libsources = [pjoin('src', x) for x in Split("""
    b64.c
    error.c
    json.c
    key.c
    key_ec.c
    keyset.c
    parse.c
    validator.c
""")]

if lenv["BUILD"] == "STATIC":
    static_library = lenv.StaticLibrary(target = "libxjwt", source = [libsources])
    Return('static_library')
elif lenv["BUILD"] == "SHARED":
    shared_library = lenv.SharedLibrary(target = "libxjwt", source = [libsources])
    Return('shared_library')
else:
    print 'Unknown build type. BUILD=%s' % lenv["BUILD"]
    Exit(1)
