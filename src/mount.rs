use crate::spec::{Mount, Spec};
use nix::mount::MsFlags;
use nix::sys::stat::{Mode, SFlag};
use nix::unistd::{chdir, mkdir};
use nix::{Error, NixPath};
use std::fmt;
use std::ops::BitAnd;

use flexi_logger::{LevelFilter, LogSpecification, Logger};
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat;

const put_old_name: &str = "oldrootfs";
const NONE: Option<&'static [u8]> = None;

//todo deal with the LABEL_MOUNT
pub fn mounts(spec: &Spec) {
    info!("starting the mounts .. ");
    ///1. check if the root & mounts are set
    if spec.root.is_none() || spec.mounts.is_none() {
        info!("no work todo, both root & mount is None ");
        return;
    }
    ///2. Ensure that 'new_root' and its parent mount don't have
    /// shared propagation (which would cause pivot_root() to
    /// return an error), and prevent propagation of mount
    /// events to the initial mount namespace
    //if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1)
    let root = b"/".as_ref();
    #[cfg(any(target_os = "linux"))]
    let result = nix::mount::mount(
        NONE,
        root,
        NONE,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        NONE,
    );
    if result.is_err() {
        info!("nix::mount::mount {:?} ", result);
        return;
    }

    /// 3. Ensure that 'rootfs' is a mount point
    /// if (mount(new_root, new_root, NULL, MS_BIND, NULL) == -1)
    let x = spec.root.as_ref().unwrap();
    let s = String::from(&x.path);
    let vec = s.into_bytes();
    let rootfs_path = vec.as_slice();
    info!(
        "the root path {:?} ",
        std::str::from_utf8(rootfs_path).unwrap()
    );
    #[cfg(any(target_os = "linux"))]
    let result = nix::mount::mount(Some(rootfs_path), rootfs_path, NONE, MsFlags::MS_BIND, NONE);
    if result.is_err() {
        info!("nix::mount::mount {:?} ", result);
        return;
    }

    ///4. Create directory to which old root will be pivoted; it must be under the new root
    let rp = std::str::from_utf8(rootfs_path).unwrap();
    let put_old_path = format!("{}/{}", rp, put_old_name);
    info!("the put_old_path {} ", put_old_path);
    let vec1 = put_old_path.into_bytes();
    let put_old_path = vec1.as_slice();
    // if (mkdir(path, 0777) == -1)
    let result = mkdir(put_old_path, Mode::S_IRWXO | Mode::S_IRWXG | Mode::S_IRWXU);
    if result.is_err() {
        info!("mkdir {:?} ", result);
        return;
    }

    ///5.  And pivot the root filesystem
    // if (pivot_root(new_root, path) == -1)
    #[cfg(any(target_os = "linux"))]
    let result = nix::unistd::pivot_root(rootfs_path, put_old_path);
    if result.is_err() {
        info!("mkdir {:?} ", result);
        return;
    }

    ///6.Switch the current working directory to "/"
    //if (chdir("/") == -1)
    let result = chdir("/");
    if result.is_err() {
        info!("chdir {:?} ", result);
        return;
    }

    ///7.Unmount old root and remove mount point
    //umount2(put_old, MNT_DETACH)
    let put_old_dir = put_old_name.as_bytes();
    #[cfg(any(target_os = "linux"))]
    let result = nix::mount::umount2(put_old_dir, nix::mount::MntFlags::MNT_DETACH);
    if result.is_err() {
        info!(
            "umount2, the old path {}, result {:?} ",
            std::str::from_utf8(put_old_dir).unwrap(),
            result
        );
        return;
    }
    let pop = std::str::from_utf8(put_old_dir).unwrap();
    let result = std::fs::remove_dir(&pop);
    if result.is_err() {
        info!("remove_dir {}, result {:?} ", pop, result);
        return;
    }

    //8.process all the config.json mounts
    do_mounts(&spec);
    //9.check if we need devices in the config.json file
    /* spec.linux.as_ref().map(|linux| {
        do_devices(&linux.devices)?;
    });*/
    // Ok(())
}

pub fn do_mounts(spec: &Spec) {
    if spec.mounts.is_none() {
        info!("no mounts .. ");
        return;
    }

    let mounts = spec.mounts.as_ref().unwrap();

    for mount in mounts {
        info!(
            "starting mount destination {}, options {:?} ",
            mount.destination, mount.mount_options
        );
        //(mount_flags:nix::mount::MsFlags,options:str)
        let (mount_flags, options) = match &mount.mount_options {
            None => {
                //get the default batch
                get_default_flags(mount)
            }
            Some(mount_options) => {
                //map these options into MsFlags
                info!("mapping the mount options {:?} ", mount_options);
                let mut flags = nix::mount::MsFlags::empty();
                let mut options: Vec<&str> = Vec::new();

                for mount_option in mount_options {
                    info!("the mount_option {:?}", mount_option);
                    //convert to MsFlag
                    let flag = get_mount_flag(mount_option);
                    if flag.is_empty() {
                        //get the option
                        info!("got an option {:?} ", mount_option);
                        options.push(mount_option);
                    } else {
                        flags.insert(flag);
                    }
                }
                (flags, Some(options))
            }
        };

        info!(
            "the mount type {:?} and mount flags {:?} ",
            mount.mount_type, mount_flags
        );

        //todo if type == None || source == None fail
        if mount.mount_type.as_ref().is_none() || mount.source.as_ref().is_none() {
            info!(
                "error : invalid mount type for {} , source {:?}, type {:?} ",
                mount.destination, mount.source, mount.mount_type
            );
            return;
        }

        info!(
            "mount source {:?} and mount flags {:?} ",
            mount.source, mount_flags
        );

        let source = mount.source.as_ref().unwrap();
        info!("source {} ", source);
        let source = source.as_bytes();
        let stats = stat::stat(source);
        let mut is_dir = false;
        if stats.is_err() {
            info!("error with stat {:?} ", stats);
        //TODO for now, lets see what will succed
        //return;
        } else {
            let stats = stats.unwrap();
            let typ = stat::SFlag::from_bits_truncate(stats.st_mode);
            info!("the type {:?} ", typ);
            is_dir = typ == SFlag::S_IFDIR;
        }

        if is_dir {
            let must_under_root = match mount.mount_type.as_ref().unwrap().as_str() {
                "sysfs" | "proc" => true,

                _ => false,
            };

            if must_under_root {
                info!("ensure is dir under root {}", mount.destination);
            }
        } else {
            info!("ensure its a file at {} ", mount.destination);
        }

        //lets mount the file
        //let target_fd = open_mount_target(&spec.root.as_ref().unwrap().path, &mount.destination);

        //check the result of the open
        if mount.destination == "cgroup" {
            info!("mounting cgroup ");
            let ret = do_mount_cgroup(mount, mount_flags);
            info!("result of mounting the cgroup {} ", ret);
        } else {
            //all others
            info!("mounting {} ", mount.destination);
            let label_houw = match mount.mount_type.as_ref().unwrap().as_str() {
                "sysfs" | "proc" => 1,
                "mqueue" => 2,

                _ => 3,
            };
            //do the mount here

            let ret = do_mount_cgroup(mount, mount_flags);
            info!("result of mounting the cgroup {} ", ret);
        }
    }
}

fn do_mount_cgroup(mount: &Mount, mount_flags: nix::mount::MsFlags) -> i32 {
    info!("mounting the {}", mount.destination);
    let source = mount.source.as_ref().unwrap().as_bytes();
    let target = mount.destination.as_bytes();
    let fs_type = mount.mount_type.as_ref().unwrap().as_bytes();

    #[cfg(any(target_os = "linux"))]
    let result = nix::mount::mount(
        Some(target),
        target,
        Some(fs_type),
        mount_flags | MsFlags::MS_BIND,
        NONE,
    );
    info!("the result {:?} ", result);
    if result.is_err() {
        info!("nix::mount::mount {:?} ", result);
        -1
    } else {
        //result todo
        1
    }
}

/*fn open_mount_target(root_path: &str, target: &str) -> i32 {
    let root_path_fd = open(root_path.as_bytes(), OFlag::empty(), Mode::empty());
    if root_path_fd.is_err() {
        info!("openat failed , path {:?}  ", root_path);
        return -1;
    }

    let fd = openat(
        root_path_fd,
        tmp.path().file_name().unwrap(),
        OFlag::O_RDONLY,
        Mode::empty(),
    )
    .unwrap();
}*/

//get the flag with the give name or return empty
pub fn get_mount_flag(mount_name: &str) -> nix::mount::MsFlags {
    info!("getting the mount flag , mount name {}", mount_name);
    match mount_name {
        "bind" => MsFlags::MS_BIND,
        "rbind" => MsFlags::MS_REC | MsFlags::MS_BIND,
        "ro" => MsFlags::MS_RDONLY,
        "rw" => MsFlags::MS_RDONLY,
        "suid" => MsFlags::MS_NOSUID,
        "nosuid" => MsFlags::MS_NOSUID,
        "dev" => MsFlags::MS_NODEV,
        "nodev" => MsFlags::MS_NODEV,
        "exec" => MsFlags::MS_NOEXEC,
        "noexec" => MsFlags::MS_NOEXEC,
        "sync" => MsFlags::MS_SYNCHRONOUS,
        "async" => MsFlags::MS_SYNCHRONOUS,
        "dirsync" => MsFlags::MS_DIRSYNC,
        "remount" => MsFlags::MS_REMOUNT,
        "mand" => MsFlags::MS_MANDLOCK,
        "nomand" => MsFlags::MS_MANDLOCK,
        "atime" => MsFlags::MS_NOATIME,
        "noatime" => MsFlags::MS_NOATIME,
        "diratime" => MsFlags::MS_NODIRATIME,
        "nodiratime" => MsFlags::MS_NODIRATIME,
        "relatime" => MsFlags::MS_RELATIME,
        "norelatime" => MsFlags::MS_RELATIME,
        "strictatime" => MsFlags::MS_STRICTATIME,
        "nostrictatime" => MsFlags::MS_STRICTATIME,
        "shared" => MsFlags::MS_SHARED,
        "rshared" => MsFlags::MS_REC | MsFlags::MS_SHARED,
        "slave" => MsFlags::MS_SLAVE,
        "rslave" => MsFlags::MS_REC | MsFlags::MS_SLAVE,
        "private" => MsFlags::MS_PRIVATE,
        "rprivate" => MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        "unbindable" => MsFlags::MS_UNBINDABLE,
        "runbindable" => MsFlags::MS_REC | MsFlags::MS_UNBINDABLE,
        //"tmpcopyup" => MsFlags::OPTION_TMPCOPYUP,
        _ => nix::mount::MsFlags::empty(),
    }
}

//return the default flags and mount options
//todo need to confim the default flags
pub fn get_default_flags(mount: &Mount) -> (nix::mount::MsFlags, Option<Vec<&str>>) {
    match mount.destination.as_str() {
        "/proc" => (nix::mount::MsFlags::empty(), None),
        "/dev/cgroup" => {
            debug!("no support for cgroupv1");
            (nix::mount::MsFlags::empty(), None)
        }
        "/sys/fs/cgroup" => {
            //bit or
            let flags = nix::mount::MsFlags::MS_NOEXEC
                | nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_STRICTATIME;
            //let options = "none,name=";
            (flags, None)
        }
        "/dev" => {
            let flags = nix::mount::MsFlags::MS_NOEXEC | nix::mount::MsFlags::MS_STRICTATIME;
            //let options = "mode=755";
            let mut vec = Vec::new();
            vec.push("mode=755");
            (flags, Some(vec))
        }
        "/dev/shim" => {
            let flags = nix::mount::MsFlags::MS_NOEXEC
                | nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV;
            //let options = "mode=1777,size=6553k";
            let mut vec = Vec::new();
            vec.push("mode=1777");
            vec.push("size=6553k");
            (flags, Some(vec))
        }
        "/dev/mqueue" => {
            let flags = nix::mount::MsFlags::MS_NOEXEC
                | nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV;
            (flags, None)
        }
        "/dev/pts" => {
            //TODO
            let flags = nix::mount::MsFlags::MS_NOEXEC
                | nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV;
            (flags, None)
        }
        "/dev/sys" => {
            let flags = nix::mount::MsFlags::MS_NOEXEC
                | nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV;
            (flags, None)
        }

        _ => {
            unreachable!()
        }
    }
}
