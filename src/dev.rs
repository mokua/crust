use crate::spec::{LinuxDevice, Spec};
use nix::fcntl::{open, openat, OFlag};
use nix::mount::MsFlags;
use nix::sys::stat::Mode;
use std::fs;

/*
default devices

/dev/null
/dev/zero
/dev/full
/dev/random
/dev/urandom
/dev/tty
/dev/console is set up if terminal is enabled in the config by bind mounting the pseudoterminal pty to /dev/console.
/dev/ptmx. A bind-mount or symlink of the container's /dev/pts/ptmx.

struct device_s needed_devs[] = { { "/dev/null", "c", 1, 3, 0666, 0, 0 },
                                  { "/dev/zero", "c", 1, 5, 0666, 0, 0 },
                                  { "/dev/full", "c", 1, 7, 0666, 0, 0 },
                                  { "/dev/tty", "c", 5, 0, 0666, 0, 0 },
                                  { "/dev/random", "c", 1, 8, 0666, 0, 0 },
                                  { "/dev/urandom", "c", 1, 9, 0666, 0, 0 },
                                  {} };
*/

const NONE: Option<&'static [u8]> = None;

//0666
fn default_devices() -> Vec<LinuxDevice> {
    vec![
        LinuxDevice::new("/dev/null", "c", 1, 3, 0666, 0, 0),
        LinuxDevice::new("/dev/zero", "c", 1, 5, 0666, 0, 0),
        LinuxDevice::new("/dev/full", "c", 1, 7, 0666, 0, 0),
        LinuxDevice::new("/dev/tty", "c", 5, 0, 0666, 0, 0),
        LinuxDevice::new("/dev/random", "c", 1, 9, 0666, 0, 0),
        LinuxDevice::new("/dev/urandom", "c", 1, 9, 0666, 0, 0),
    ]
}
/*const fn bop_ct() -> Mode {
    Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IROTH | Mode::S_IWOTH | Mode::S_IRGRP | Mode::S_IWGRP
}*/

pub fn create_devices(spec: &Spec) {
    info!("creating devices");
    if spec.root.is_none() {
        info!("root not defined");
        return;
    }

    let dev_res = open("dev", OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty());
    if dev_res.is_err() {
        info!("open failed ,error {:?}  ", dev_res);
        return;
    }

    let dev_path_fd = dev_res.unwrap();
    let devices = spec.linux.as_ref().unwrap().devices.as_ref().unwrap();
    let binds = false; //TODO
    for device in devices {
        info!("device {:?} ", device);
        create_it(dev_path_fd, device, binds);
    }
    //add default devices
    for default_device in default_devices() {
        create_it(dev_path_fd, &default_device, binds);
    }
    //need to add the default system links
}

fn create_it(dev_dir_fd: i32, device: &LinuxDevice, binds: bool) {
    info!(
        " dev_dir_fd {} , device {:?} binds {}",
        dev_dir_fd, device, binds
    );
    if binds {
        //fd = openat (devfd, rel_dev, O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0700);
        let device_path = device.path.as_str().as_bytes();
        let mode = Mode::S_IWUSR | Mode::S_IRUSR | Mode::S_IXUSR; //0700
        let result = openat(
            dev_dir_fd,
            device_path,
            OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            mode,
        );

        if result.is_err() {
            info!("error create device at {}", device.path);
            return;
        }

        let device_fd = result.unwrap();
        let target_str = format!("/proc/self/fd/{}", device_fd);
        let target = target_str.as_bytes();
        //mount (NULL, "/proc/self/fd/%d", NULL, rec | MS_BIND | MS_PRIVATE, NULL);
        #[cfg(any(target_os = "linux"))]
        let result = nix::mount::mount(
            NONE,
            target,
            NONE,
            MsFlags::MS_PRIVATE | MsFlags::MS_BIND,
            NONE,
        );
        info!("the result of mounting {:?} is {:?} ", target_str, result);
        if result.is_err() {
            info!("nix::mount::mount {:?} ", result);
            -1
        } else {
            //result todo
            1
        };
    } else {
        info!("make dev: major {} minor {}", device.major, device.minor);
        let dev = nix::sys::stat::makedev(device.major, device.minor);
        info!("make dev res {} ", dev);
        // todo check the path device.destination
        //change the path from /dev/sda ==> sda
        let device_type = match device.device_type.as_str() {
            "b" => nix::sys::stat::SFlag::S_IFBLK,
            "p" => nix::sys::stat::SFlag::S_IFIFO,
            _ => nix::sys::stat::SFlag::S_IFCHR,
        };
        info!("the device type {:?} ", device_type);

        let file_mode = match device.file_mode {
            None => {
                Mode::S_IRUSR
                    | Mode::S_IWUSR
                    | Mode::S_IROTH
                    | Mode::S_IWOTH
                    | Mode::S_IRGRP
                    | Mode::S_IWGRP
            } //device.mode = 0666;
            Some(mode) => {
                let str = format!("{:b}", mode);
                let m = u32::from_str_radix(str.as_str(), 2).unwrap();
                nix::sys::stat::Mode::from_bits(m).unwrap()
            }
        };

        let target = device.path.as_str().as_bytes();
        let result = nix::sys::stat::mknod(target, device_type, file_mode, dev);
        //todo
        info!("the result from mknod {:?} ", result);
    }
}

//TODO
fn check_running_in_user_namespace() {
    //read_all_file ("/proc/self/uid_map", &buffer, &len, err)
    //strstr (buffer, "4294967295") ? 0 : 1;
}
