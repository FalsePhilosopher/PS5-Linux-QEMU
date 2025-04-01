out = build_library('libfakexen', ['libc', 'libboot', 'libvm', 'liblog'])

def extra_deps(cmdline):
    a, b = cmdline.split(' ')
    return [], [a, b]
