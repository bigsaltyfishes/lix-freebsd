#include "lix/libutil/mount.hh"
#include "lix/libutil/error.hh"
#include "lix/libutil/file-system.hh"
#include "lix/libutil/logging.hh"
#if __linux__
#include <sys/mount.h>

namespace nix {

void bindPath(const Path & source, const Path & target, bool optional) {
    debug("bind mounting '%1%' to '%2%'", source, target);

    auto bindMount = [&]() {
        if (mount(source.c_str(), target.c_str(), "", MS_BIND | MS_REC, 0) == -1)
            throw SysError("bind mount from '%1%' to '%2%' failed", source, target);
    };

    auto maybeSt = maybeLstat(source);
    if (!maybeSt) {
        if (optional)
            return;
        else
            throw SysError("getting attributes of path '%1%'", source);
    }
    auto st = *maybeSt;

    if (S_ISDIR(st.st_mode)) {
        createDirs(target);
        bindMount();
    } else if (S_ISLNK(st.st_mode)) {
        // Symlinks can (apparently) not be bind-mounted, so just copy it
        createDirs(dirOf(target));
        copyFile(source, target, {});
    } else {
        createDirs(dirOf(target));
        writeFile(target, "");
        bindMount();
    }
}

}

#elif __FreeBSD__
#include <sys/param.h>
#include <sys/mount.h>

namespace nix {

void unmountAll(Path & path)
{
    int count;
    struct statfs * mntbuf;
    if ((count = getmntinfo(&mntbuf, MNT_WAIT)) < 0) {
        throw SysError("Couldn't list mounts while unmounting %1%", path);
    }

    for (int i = 0; i < count; i++) {
        Path mounted(mntbuf[i].f_mntonname);
        if (mounted.starts_with(path)) {
            if (unmount(mounted.c_str(), 0) < 0) {
                throw SysError("Failed to unmount path %1%", mounted);
            }
        }
    }
}

}

#endif
