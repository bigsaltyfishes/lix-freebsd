#pragma once
///@file

#include "lix/libutil/types.hh"

#if __linux__
namespace nix {

/**
 * Bind-mount file or directory from `source` to `destination`.
 * If source does not exist this will fail unless `optional` is set
 */
void bindPath(const Path & source, const Path & target, bool optional = false);

}
#elif __FreeBSD__
namespace nix {
/**
 * Unmount a directory and all its subdirectories.
 * Useful on FreeBSD since jails don't have separate mount namespaces
 * Succeeds even if path does not exist
 */
void unmountAll(Path & path);
}
#endif
