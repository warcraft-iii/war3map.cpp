
target("war3map")
    set_kind('shared')
    add_headerfiles('**.h')
    add_files('**.cpp')
    add_includedirs(path.join(os.projectdir(), 'include/war3map.cpp/'))
    add_values('charset', 'MBCS')
