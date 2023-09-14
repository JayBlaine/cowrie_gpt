def resolve_path(pathspec: str, cwd: str) -> str:
    """
    From cowrie
    """
    cwdpieces: list[str] = []
    # If a path within home directory is specified, convert it to an absolute path
    if pathspec.startswith("~/"):
        path = '/home/' + pathspec[2:]
    else:
        path = pathspec

    pieces = path.rstrip("/").split("/")

    if path[0] == "/" or path[0] in ['~', '~/']:  # added or for if just ~ send to reset like / directory
        cwdpieces = []
    else:
        cwdpieces = [x for x in cwd.split("/") if len(x) and x is not None]

    while 1:
        if not len(pieces):
            break
        piece = pieces.pop(0)
        if piece == "..":
            if len(cwdpieces):
                cwdpieces.pop()
            continue
        if piece in (".", ""):
            continue
        if piece == '~':  # ADDED to clear cwd to just home
            cwdpieces = ['~']
        else:
            cwdpieces.append('{}'.format(piece))

    if len(cwdpieces) > 0:
        return "/{}".format("/".join(cwdpieces)) if cwdpieces[0] != '~' else "/{}".format("/".join(cwdpieces)).lstrip('/')
    else:
        return "/"


def update_input_str(input_cmd: str, fs_loc: str):
    """
    Update directory shown in input

    :param input_list:
    :param fs_loc:
    :return:
    """
    iter_list = input_cmd.split(' ')
    if iter_list[0] == 'cd':
        fs_loc = resolve_path(iter_list[1], fs_loc)

    return fs_loc