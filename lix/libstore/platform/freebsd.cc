#include "lix/libstore/build/worker.hh"
#include "lix/libstore/platform/freebsd.hh"
#include "lix/libutil/mount.hh"
#include "lix/libutil/regex.hh"
#include "lix/libutil/strings.hh"

#include <db.h>
#include <net/if.h>
#include <pwd.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#include <libprocstat.h>
#include <vector>

namespace nix {

static void readSysctlRoots(const char * name, UncheckedRoots & unchecked)
{
    size_t len = 0;
    std::string value;
    if (int err = sysctlbyname(name, nullptr, &len, nullptr, 0) < 0) {
        if (err == ENOENT || err == EACCES) {
            return;
        } else {
            throw SysError(err, "sysctlbyname %1%", name);
        }
    }

    value.resize(len, ' ');
    if (int err = sysctlbyname(name, value.data(), &len, nullptr, 0) < 0) {
        if (err == ENOENT || err == EACCES) {
            return;
        } else {
            throw SysError(err, "sysctlbyname %1%", name);
        }
    }

    for (auto & path : tokenizeString<Strings>(value, ";")) {
        unchecked[path].emplace(fmt("{{sysctl:%1%}}", name));
    }
}

struct ProcstatDeleter
{
    void operator()(struct procstat * ps)
    {
        procstat_close(ps);
    }
};

template<auto del>
struct ProcstatReferredDeleter
{
    struct procstat * ps;

    ProcstatReferredDeleter(struct procstat * ps) : ps(ps) {}

    template<typename T>
    void operator()(T * p)
    {
        del(ps, p);
    }
};

void FreeBSDLocalStore::findPlatformRoots(UncheckedRoots & unchecked)
{
    readSysctlRoots("kern.module_path", unchecked);

    auto storePathRegex = regex::storePathRegex(config().storeDir);

    auto ps = std::unique_ptr<struct procstat, ProcstatDeleter>(procstat_open_sysctl());
    if (!ps) {
        throw SysError("procstat_open_sysctl");
    }

    auto procs = std::unique_ptr<struct kinfo_proc[], ProcstatReferredDeleter<procstat_freeprocs>>(
        nullptr, ps.get()
    );
    auto files = std::unique_ptr<struct filestat_list, ProcstatReferredDeleter<procstat_freefiles>>(
        nullptr, ps.get()
    );

    unsigned int numprocs = 0;
    procs.reset(procstat_getprocs(ps.get(), KERN_PROC_PROC, 0, &numprocs));
    if (!procs || numprocs == 0) {
        throw SysError("procstat_getprocs");
    };

    for (unsigned int procidx = 0; procidx < numprocs; procidx++) {
        // Includes file descriptors, executable, cwd,
        // and mmapped files (including dynamic libraries)
        files.reset(procstat_getfiles(ps.get(), &procs[procidx], 1));
        // We only have permission if we're root so just skip it if we fail
        if (!files) {
            continue;
        }

        for (struct filestat * file = files->stqh_first; file; file = file->next.stqe_next) {
            if (!file->fs_path) {
                continue;
            }

            std::string role;
            if (file->fs_uflags & PS_FST_UFLAG_CTTY) {
                role = "ctty";
            } else if (file->fs_uflags & PS_FST_UFLAG_CDIR) {
                role = "cwd";
            } else if (file->fs_uflags & PS_FST_UFLAG_JAIL) {
                role = "jail";
            } else if (file->fs_uflags & PS_FST_UFLAG_RDIR) {
                role = "root";
            } else if (file->fs_uflags & PS_FST_UFLAG_TEXT) {
                role = "text";
            } else if (file->fs_uflags & PS_FST_UFLAG_TRACE) {
                role = "trace";
            } else if (file->fs_uflags & PS_FST_UFLAG_MMAP) {
                role = "mmap";
            } else {
                role = fmt("fd/%1%", file->fs_fd);
            }

            unchecked[file->fs_path].emplace(fmt("{procstat:%1%/%2%}", procs[procidx].ki_pid, role)
            );
        }

        auto env_name = fmt("{procstat:%1%/env}", procs[procidx].ki_pid);
        // No need to free, the buffer is reused on next call and deallocated in procstat_close
        char ** env = procstat_getenvv(ps.get(), &procs[procidx], 0);
        if (env == nullptr) {
            continue;
        }

        for (size_t i = 0; env[i]; i++) {
            auto envString = std::string(env[i]);

            auto envEnd = std::sregex_iterator{};
            for (auto match =
                     std::sregex_iterator{envString.begin(), envString.end(), storePathRegex};
                 match != envEnd;
                 match++)
            {
                unchecked[match->str()].emplace(env_name);
            }
        }
    }
}

struct PasswordEntry
{
    std::string name;
    uid_t uid;
    gid_t gid;
    std::string description;
    Path home;
    Path shell;
};

static void free_db(DB * db)
{
    if (db != nullptr) {
        (db->close)(db);
    }
}

// Database open flags from FreeBSD, in case they're necessary for compatibility
static const HASHINFO db_flags = {
    .bsize = 4096,
    .ffactor = 32,
    .nelem = 256,
    .cachesize = 2 * 1024 * 1024,
    .hash = nullptr,
    .lorder = BIG_ENDIAN,
};

// Password database version
// Version 4 has been current since 2003
static const uint8_t dbVersion = 4;

static void serializeString(std::vector<uint8_t> & buf, std::string const & str)
{
    buf.reserve(buf.size() + str.size() + 1);
    buf.insert(buf.end(), str.begin(), str.end());
    buf.push_back(0);
}

static void serializeInt(std::vector<uint8_t> & buf, uint32_t num)
{
    buf.reserve(buf.size() + sizeof(num));
    // Always big endian
    buf.push_back((num >> 24) & 0xff);
    buf.push_back((num >> 16) & 0xff);
    buf.push_back((num >> 8) & 0xff);
    buf.push_back((num >> 0) & 0xff);
}

static std::vector<uint8_t> byNameKey(std::string const & name)
{
    std::vector<uint8_t> buf{_PW_VERSIONED(_PW_KEYBYNAME, dbVersion)};
    buf.reserve(1 + name.size());
    // We can't use serializeString since that's null terimated
    buf.insert(buf.end(), name.begin(), name.end());

    return buf;
}

static std::vector<uint8_t> byNumKey(uint32_t num)
{
    std::vector<uint8_t> buf{_PW_VERSIONED(_PW_KEYBYNUM, dbVersion)};
    serializeInt(buf, num);

    return buf;
}

static std::vector<uint8_t> byUidKey(uid_t uid)
{
    std::vector<uint8_t> buf{_PW_VERSIONED(_PW_KEYBYUID, dbVersion)};
    serializeInt(buf, uid);

    return buf;
}

static void createPasswordFiles(Path & chrootRootDir, std::vector<PasswordEntry> & users)
{
    std::unique_ptr<DB, decltype(&free_db)> db(
        dbopen(
            (chrootRootDir + "/etc/pwd.db").c_str(),
            O_CREAT | O_RDWR | O_EXCL,
            0644,
            DB_HASH,
            &db_flags
        ),
        &free_db
    );

    if (db == nullptr) {
        throw SysError("Could not create password database");
    }

    auto dbInsert = [&db](std::vector<uint8_t> key_buf, std::vector<uint8_t> & value_buf) {
        DBT key = {key_buf.data(), key_buf.size()};
        DBT value = {value_buf.data(), value_buf.size()};

        if ((db->put)(db.get(), &key, &value, R_NOOVERWRITE) == -1) {
            throw SysError("Could not write to password database");
        }
    };

    // Annoyingly DBT doesn't have const pointers so we need this whole shuffle
    std::string versionKeyStr(_PWD_VERSION_KEY);
    std::vector<uint8_t> versionKey(versionKeyStr.begin(), versionKeyStr.end());
    std::vector<uint8_t> versionValue{dbVersion};
    dbInsert(versionKey, versionValue);

    for (size_t i = 0; i < users.size(); i++) {
        auto user = users[i];

        // flags for non-empty fields
        uint32_t fields =
            _PWF_NAME | _PWF_PASSWD | _PWF_UID | _PWF_GID | _PWF_GECOS | _PWF_DIR | _PWF_SHELL;

        std::vector<uint8_t> buf;
        serializeString(buf, user.name);
        // pw_password is always "*" in the insecure database
        serializeString(buf, std::string("*"));
        serializeInt(buf, user.uid);
        serializeInt(buf, user.gid);
        // pw_change = 0 means no requirement to change password
        serializeInt(buf, 0);
        // pw_class is empty since we don't make a class database
        serializeString(buf, std::string(""));
        serializeString(buf, user.description);
        serializeString(buf, user.home);
        serializeString(buf, user.shell);
        // pw_expire = 0 means password does not expire
        serializeInt(buf, 0);
        serializeInt(buf, fields);

        dbInsert(byNameKey(user.name), buf);
        // _PW_KEYBYNUM is 1-indexed
        dbInsert(byNumKey(i + 1), buf);
        dbInsert(byUidKey(user.uid), buf);
    }

    // FreeBSD libc doesn't use /etc/passwd, but some software might
    std::string passwdContent = "";
    for (auto user : users) {
        passwdContent.append(
            fmt("%s:*:%d:%d:%s:%s:%s\n",
                user.name,
                user.uid,
                user.gid,
                user.description,
                user.home,
                user.shell)
        );
    }

    writeFile(chrootRootDir + "/etc/passwd", passwdContent);

    // No need to make /etc/master.passwd or /etc/spwd.db,
    // our build user wouldn't be able to read them anyway
}

void FreeBSDLocalDerivationGoal::prepareSandbox()
{
    chrootRootDir = worker.store.Store::toRealPath(drvPath) + ".chroot";
    // Make sure we're prepared if unmount failed previously
    unmountAll(chrootRootDir);

    // clang-format off
    std::vector<PasswordEntry> users {{
        "root",
        0,
        0,
        "Nix build user",
        settings.sandboxBuildDir,
        "/noshell"
    }, {
        "nixbld",
        sandboxUid(),
        sandboxGid(),
        "Nix build user",
        settings.sandboxBuildDir,
        "/noshell"
    }, {
        "nobody",
        65534,
        65534,
        "Nobody",
        "/",
        "/noshell"
    }};
    // clang-format on
    basicChrootSetup();

    createPasswordFiles(chrootRootDir, users);

    // FreeBSD doesn't have a group database, just write a text file
    writeFile(
        chrootRootDir + "/etc/group",
        fmt("root:x:0:\n"
            "nixbld:!:%1%:\n"
            "nogroup:x:65534:\n",
            sandboxGid())
    );

    // Linux waits until after entering the child to start mounting so it doesn't
    // pollute the root mount namespace.
    // FreeBSD doesn't have mount namespaces, so there's no reason to wait.

    auto devpath = chrootRootDir + "/dev";
    mkdir(devpath.c_str(), 0555);
    mkdir((chrootRootDir + "/bin").c_str(), 0555);
    char errmsg[255] = "";
    struct iovec iov[8] = {
        {.iov_base = (void *) "fstype", .iov_len = sizeof("fstype")},
        {.iov_base = (void *) "devfs", .iov_len = sizeof("devfs")},
        {.iov_base = (void *) "fspath", .iov_len = sizeof("fspath")},
        {.iov_base = (void *) devpath.c_str(), .iov_len = devpath.length() + 1},
        {.iov_base = (void *) "ruleset", .iov_len = sizeof("ruleset")},
        {.iov_base = (void *) "4", .iov_len = sizeof("4")},
        {.iov_base = (void *) "errmsg", .iov_len = sizeof("errmsg")},
        {.iov_base = (void *) errmsg, .iov_len = sizeof(errmsg)},
    };
    if (nmount(iov, 6, 0) < 0) {
        throw SysError("Failed to mount jail /dev: %1%", errmsg);
    }
    for (auto & i : pathsInChroot) {
        char errmsg[255];
        errmsg[0] = 0;

        if (i.second.source == "/proc") {
            continue; // backwards compatibility
        }
        auto path = chrootRootDir + i.first;

        struct stat stat_buf;
        if (stat(i.second.source.c_str(), &stat_buf) < 0) {
            throw SysError("stat");
        }

        // mount points must exist and be the right type
        if (S_ISDIR(stat_buf.st_mode)) {
            createDirs(path);
        } else {
            createDirs(dirOf(path));
            writeFile(path, "");
        }

        struct iovec iov[8] = {
            {.iov_base = (void *) "fstype", .iov_len = sizeof("fstype")},
            {.iov_base = (void *) "nullfs", .iov_len = sizeof("nullfs")},
            {.iov_base = (void *) "fspath", .iov_len = sizeof("fspath")},
            {.iov_base = (void *) path.c_str(), .iov_len = path.length() + 1},
            {.iov_base = (void *) "target", .iov_len = sizeof("target")},
            {.iov_base = (void *) i.second.source.c_str(), .iov_len = i.second.source.length() + 1},
            {.iov_base = (void *) "errmsg", .iov_len = sizeof("errmsg")},
            {.iov_base = (void *) errmsg, .iov_len = sizeof(errmsg)},
        };
        if (nmount(iov, 8, 0) < 0) {
            throw SysError("Failed to mount nullfs for %1% - %2%", path, errmsg);
        }
    }

    /* Fixed-output derivations typically need to access the
       network, so give them access to /etc/resolv.conf and so
       on. */
    if (!derivationType->isSandboxed()) {
        // Only use nss functions to resolve hosts and
        // services. Don’t use it for anything else that may
        // be configured for this system. This limits the
        // potential impurities introduced in fixed-outputs.
        writeFile(chrootRootDir + "/etc/nsswitch.conf", "hosts: files dns\nservices: files\n");

        /* N.B. it is realistic that these paths might not exist. It
           happens when testing Nix building fixed-output derivations
           within a pure derivation. */
        for (auto & path : {"/etc/resolv.conf", "/etc/services", "/etc/hosts"}) {
            if (pathExists(path)) {
                // Copy the actual file, not the symlink, because we don't know where
                // the symlink is pointing, and we don't want to chase down the entire
                // chain.
                //
                // This means if your network config changes during a FOD build,
                // the DNS in the sandbox will be wrong. However, this is pretty unlikely
                // to actually be a problem, because FODs are generally pretty fast,
                // and machines with often-changing network configurations probably
                // want to run resolved or some other local resolver anyway.
                //
                // There's also just no simple way to do this correctly, you have to manually
                // inotify watch the files for changes on the outside and update the sandbox
                // while the build is running (or at least that's what Flatpak does).
                //
                // I also just generally feel icky about modifying sandbox state under a build,
                // even though it really shouldn't be a big deal. -K900
                copyFile(path, chrootRootDir + path, {.followSymlinks = true});
            }
        }

        if (settings.caFile != "" && pathExists(settings.caFile)) {
            // For the same reasons as above, copy the CA certificates file too.
            // It should be even less likely to change during the build than resolv.conf.
            createDirs(chrootRootDir + "/etc/ssl/certs");
            copyFile(
                settings.caFile,
                chrootRootDir + "/etc/ssl/certs/ca-certificates.crt",
                {.followSymlinks = true}
            );
        }
    }
}

Pid FreeBSDLocalDerivationGoal::startChild(std::function<void()> openSlave)
{
    if (useChroot) {
        if (derivationType->isSandboxed()) {
            privateNetwork = true;
        }
    }

    return LocalDerivationGoal::startChild(openSlave);
}

void registerLocalStore()
{
    StoreImplementations::add<FreeBSDLocalStore, LocalStoreConfig>();
}

}
