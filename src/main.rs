mod caps;
mod dev;
mod mount;
mod resources;
mod spec;

use crate::resources::LinuxResources;
use clap::{App, Arg};

//use crate::CLONE_NEWNS;
//use libc::CLONE_NEWNS;
use nix::sys::socket::SockFlag;
use nix::sys::socket::{socketpair, AddressFamily, SockType};
use nix::sys::utsname::uname;
use nix::unistd::{execve, execvp, fork, gethostname, pipe, sethostname, ForkResult, Pid, Uid};
use std::cmp::min;
use std::fmt::Write;
use std::process::{exit, Command, ExitStatus, Stdio};
use std::{fs, io, process, thread, time};

extern crate nix;
use crate::spec::{Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompArg, Process, Spec};
use nix::errno::Errno::EPERM;
use nix::sys::time::{TimeSpec, TimeValLike};
use nix::{sched, Error};
use seccomp_sys::scmp_arch::SCMP_ARCH_NATIVE;
use seccomp_sys::{
    scmp_compare, seccomp_arch_add, seccomp_attr_set, seccomp_init, seccomp_load, seccomp_release,
    seccomp_rule_add, seccomp_rule_add_array, seccomp_syscall_resolve_name,
};
use std::ffi::CString;
use std::fs::File;
use std::os::raw::c_int;
use std::os::unix::io::IntoRawFd;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

#[macro_use]
extern crate log;
extern crate flexi_logger;

use flexi_logger::{LevelFilter, LogSpecification, Logger};

pub struct ChildConfig {
    argc: u8,
    uid: Uid,
    fd: u8,
    host_name: &'static str,
    argv: Vec<&'static str>,
    mount_dir: &'static str,
}

const STACK_SIZE: usize = 1024 * 1024;

fn main() {
    // Hard code the trace level as our minimum logging level
    let log_config = LogSpecification::default(LevelFilter::Trace).build();

    Logger::with(log_config)
        .format(flexi_logger::opt_format) // Specify how we want the logs formatted
        .start()
        .unwrap();

    // Logging is ready. Let's use it to debug our complex algorithm
    info!("we start!");

    //let mut buf = [0u8; 64];
    //let hostname_cstr = gethostname(&mut buf).expect("Failed getting hostname");
    //let hostname = hostname_cstr.to_str().expect("Hostname wasn't valid UTF-8");
    //println!("Hostname: {}", hostname);
    let matches = App::new("crust")
        .version("1.0")
        .author("Richard Mokua <mokua83ke@gmail.com>")
        .about("Containers in Rust ")
        .arg(
            Arg::with_name("config.json")
                .short("config")
                .long("config")
                .help("Config.json file ")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("command")
                .short("c")
                .long("command")
                .help("Sets the command to run inside the container")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mount_dir")
                .short("m")
                .long("mount")
                .help("the mount directory")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cgroup_path")
                .short("cg")
                .long("cgroup_path")
                .help("the cgroup directory")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("uid")
                .short("u")
                .long("uid")
                .help("Sets the user id")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    // Gets a value for config if supplied by user, or defaults to "default.conf"
    let command = matches.value_of("command").unwrap_or("default.conf");
    debug!("command: {}", command);
    let md = matches.value_of("mount_dir").unwrap();
    debug!("mound dir: {}", md);
    let uid = matches.value_of("uid").unwrap();
    debug!("uid: {}", uid);

    let config_json = matches.value_of("config.json").unwrap();
    debug!("config_json: {}", config_json);

    let cgroup_path = matches.value_of("cgroup_path").unwrap();
    debug!("cgroup_path: {}", cgroup_path);

    //<<check-linux-version>>
    debug!("Validating the linux version .. ");
    let host = uname();
    debug!(
        "utsname : release: {:?}, version:  {:?}, machine: {:?}",
        host.release(),
        host.version(),
        host.machine()
    );

    let host_args: Vec<&str> = host.release().split(".").collect();

    let major_str = host_args[0];
    let minor_str = host_args[1];
    let major = major_str.parse::<i32>().unwrap();
    let minor = minor_str.parse::<i32>().unwrap();

    debug!("args : major {}, minor {} ", major, minor);

    if major != 4 && minor < 7 && "x86_64" != host.machine() {
        debug!("not matching...");
        exit(78);
    }

    let uid = uid.parse::<i32>().unwrap();

    let child_config = ChildConfig {
        argc: 0,
        uid: Uid::from_raw(uid as u32),
        fd: 0,
        host_name: "containerd",
        argv: vec![],
        mount_dir: "",
    };

    //update linux cgroup resources
    let json = fs::read_to_string(config_json).unwrap();
    debug!("the json file ==> ");
    debug!("{}", json);
    let spec: Spec = serde_json::from_str(&json).unwrap();
    let linux = spec.linux.as_ref().unwrap();
    let cgroup_resources: &LinuxResources = &linux.resources.as_ref().unwrap();
    let res = LinuxResources::install_resources(&cgroup_resources, &child_config, cgroup_path);
    match res {
        Ok(_) => {
            debug!("installed resources")
        }
        Err(_) => {
            debug!("error installation resources")
        }
    }
    //check response!
    //<<namespaces>>

    // Create pipe to communicate between main and command process.
    let (child_fd, parent_fd) = pipe().unwrap();

    let child = || child(child_fd, &spec);
    // Clone command process.
    let ref mut stack: [u8; STACK_SIZE] = [0; STACK_SIZE];
    //println!("flag {:?}", flags);
    //let clone_flags = libc::CLONE_NEWNET;
    #[cfg(any(target_os = "linux"))]
    let mut clone_flags = nix::sched::CloneFlags::CLONE_NEWPID;
    #[cfg(any(target_os = "linux"))]
    clone_flags.insert(nix::sched::CloneFlags::CLONE_NEWNET);
    #[cfg(any(target_os = "linux"))]
    clone_flags.insert(nix::sched::CloneFlags::CLONE_NEWUSER);
    #[cfg(any(target_os = "linux"))]
    clone_flags.insert(nix::sched::CloneFlags::CLONE_NEWNS);
    #[cfg(any(target_os = "linux"))]
    clone_flags.insert(nix::sched::CloneFlags::CLONE_NEWUTS);
    #[cfg(any(target_os = "linux"))]
    clone_flags.insert(nix::sched::CloneFlags::CLONE_NEWIPC);
    #[cfg(any(target_os = "linux"))]
    let p = nix::sched::clone(Box::new(child), stack, clone_flags, None) //Some(Signal::SIGCHLD)
        .expect("Failed to spawn the child");
    info!("clone result {}", p);
    // not sure why the following line is even needed
    info!("flags {:?}", clone_flags);

    /* Update the UID and GID maps in the child */
    prepare_userns(p);

    //done,signal child
    info!("signalling child to wake up");
    nix::unistd::write(parent_fd, b"OK").unwrap();
}

fn child(child_fd: i32, spec: &Spec) -> isize {
    println!(
        "starting the child, the fd on the child process {:?}",
        child_fd
    );

    let mut buf = [0u8; 2];
    let res = nix::unistd::read(child_fd, &mut buf);
    match res {
        Ok(size) => println!("read amount {}", size),
        Err(_) => println!("error reading"),
    }

    let res = sethostname(&spec.hostname);
    match res {
        Ok(_) => {
            println!("managed to sethostname")
        }
        Err(err) => {
            println!("unable to set hostname {:?} ", err)
        }
    }
    //sysctl
    //libcrun_set_sysctl

    //mounts
    println!("calling to mounts ...");
    let result = mount::mounts(&spec);
    println!("mount result {:?} ", result);

    info!("print the directory ");
    let paths = fs::read_dir(".").unwrap();

    for path in paths {
        println!("Name: {}", path.unwrap().path().display());
        //if path.unwrap().file_type().unwrap().is_dir() {}
    }

    //create_missing_devs
    info!("creating devices ");
    dev::create_devices(&spec);
    //set the syscalls
    //todo get this from the user inout config.json
    spec.linux.as_ref().map(|linux| {
        linux.seccomp.as_ref().map(|seccomp| {
            syscalls(&seccomp);
        });
    });
    //capabilities
    spec.process.as_ref().map(|process| {
        process
            .capabilities
            .as_ref()
            .map(|capabilities| caps::install_caps(&capabilities));
    });

    /* Command::new("bash")
    .current_dir("/bin")
    .stdin(Stdio::inherit())
    .stdout(Stdio::inherit())
    //.arg("sh")
    // .arg("echo hello")
    .spawn()
    .expect("failed to execute process");*/

    ///* Execute a shell command */
    println!("starting shell ... ");
    let args: &[std::ffi::CString] = &[];
    /* let sh = CString::new("sh").expect("CString::new failed");
    let args: &[std::ffi::CString] = &[];
    let e = CString::new("PS1=-[ns-process]- #").expect("CString::new failed");
    */

    let env: &[std::ffi::CString] = &[]; //
    execve(&CString::new("/bin/bash").unwrap().as_c_str(), args, env);
    println!("execve returned, error");

    thread::sleep(Duration::from(TimeSpec::minutes(20)));
    2
}

/// Update the mapping file 'map_file', A UID or
/// GID mapping consists of one or more newline-delimited records
/// of the form:
///    ID_inside-ns    ID-outside-ns   length
fn prepare_userns(child_pid: Pid) {
    info!("prepare ns in parent procees, {:?}", child_pid.as_raw());
    let mut buffer = String::new();
    let path = format!("/proc/{}/uid_map", child_pid.as_raw());
    writeln!(&mut buffer, "0\t{}\t1", child_pid.as_raw());
    let rs = fs::write(&path, &buffer);
    match rs {
        Ok(_) => {
            println!("managed to write to the ns path {}", path)
        }
        Err(err) => {
            println!("error {:?} to write to the path {}", err, path)
        }
    }

    //todo uid_map
    let mut buffer = String::new();
    let path = format!("/proc/{}/setgroups", child_pid.as_raw());
    writeln!(&mut buffer, "deny");
    let rs = fs::write(&path, &buffer);
    match rs {
        Ok(_) => {
            info!("managed to write to the ns path {}", path)
        }
        Err(err) => {
            info!("error {:?} to write to the path {}", err, path)
        }
    }

    let mut buffer = String::new();
    let path = format!("/proc/{}/gid_map", child_pid.as_raw());
    writeln!(&mut buffer, "0\t{}\t1", child_pid.as_raw());
    let rs = fs::write(&path, &buffer);
    match rs {
        Ok(_) => {
            info!("managed to write to the ns path {}", path)
        }
        Err(err) => {
            info!("error {:?} to write to the path {}", err, path)
        }
    }
}

///  setup_seccomp initializes seccomp and loads our BPF program that filters
/// syscalls into the kernel */
//todo return results & clean_up
fn syscalls(seccomp: &LinuxSeccomp) {
    info!("syscalls -- seccomp ");
    if seccomp.syscalls.is_none() {
        //return early
        info!("syscalls empty,  return early");
        return;
    }
    let syscalls = seccomp.syscalls.as_ref().unwrap();
    //let defualt_action seccomp.default_action.to_string();
    let def_action = match seccomp.default_action {
        LinuxSeccompAction::ActKill => seccomp_sys::SCMP_ACT_KILL,
        LinuxSeccompAction::ActKillProcess => seccomp_sys::SCMP_ACT_KILL_PROCESS,
        LinuxSeccompAction::ActKillThread => seccomp_sys::SCMP_ACT_KILL_PROCESS,
        LinuxSeccompAction::ActTrap => seccomp_sys::SCMP_ACT_TRAP,
        //LinuxSeccompAction::ActErrno => seccomp_sys::SCMP_ACT_ERRNO,//todo
        //LinuxSeccompAction::ActTrace => seccomp_sys::SCMP_ACT_TRACE() //todo
        LinuxSeccompAction::ActAllow => seccomp_sys::SCMP_ACT_ALLOW,
        LinuxSeccompAction::ActLog => seccomp_sys::SCMP_ACT_ALLOW, //todo
        _ => {
            info!("fall through");
            seccomp_sys::SCMP_ACT_ALLOW
        }
    };

    unsafe {
        /* Initialize the seccomp filter state */
        let ctx = seccomp_init(def_action).as_mut();
        if ctx.is_none() {
            info!("seccomp_init failed ... , returned null");
            return;
        }
        let ctx = ctx.unwrap();
        //check the architecture if its supported
        //todo check the
        if seccomp.architectures.is_none() {
            info!("seccomp.architectures not valid .. ");
            return;
        }

        let architectures = seccomp.architectures.as_ref().unwrap();

        for architecture in architectures {
            //architecture.to_string()
            //todo arch_token = seccomp_arch_resolve_name (architecture);
            let arch_token = seccomp_sys::scmp_arch::SCMP_ARCH_NATIVE;
            let result = seccomp_arch_add(ctx, arch_token as u32);
            //todo check the return types
            ///-EDOM  Architecture specific failure.
            //
            ///-EEXIST
            //               In the case of seccomp_arch_add() the architecture already
            //               exists and in the case of seccomp_arch_remove() the
            //               architecture does not exist.
            //
            //        -EINVAL
            //               Invalid input, either the context or architecture token is
            //               invalid.
            //
            //        -ENOMEM
            //               The library was unable to allocate enough memory.
            if result != 0 && result != -libc::EEXIST {
                info!("seccomp adding architecture failed!, result {} ", result);
                seccomp_release(ctx);
                return;
            }
        }

        for syscall in syscalls {
            println!("looping through syscalls  ");
            let errno_ret = syscall.errno_ret.unwrap_or(libc::EPERM);
            let action = &syscall.action;
            if action.to_u32() == seccomp.default_action.to_u32() {
                continue;
            }

            for name in &syscall.names {
                println!("syscall name {} ", name);
                let c_str = CString::new(name.as_str()).unwrap();
                let syscall_nbr = seccomp_syscall_resolve_name(c_str.as_ptr() as *const i8);
                if syscall_nbr == seccomp_sys::__NR_SCMP_ERROR {
                    println!(
                        "invalid seccomp syscall {} and syscall nbr {}",
                        name, syscall_nbr
                    );
                    seccomp_release(ctx);
                    return;
                }

                match &syscall.args {
                    None => {
                        println!("calling seccomp_rule_add, without args  ");
                        let result = seccomp_rule_add(ctx, action.to_u32(), syscall_nbr, 0);
                        if result < 0 {
                            println!("seccomp_rule_add failed for {} action {} ", name, action);
                            seccomp_release(ctx);
                            return;
                        }
                    }
                    Some(args) => {
                        println!("calling seccomp_rule_add, with args  ");
                        let mut multiple_args = false;
                        //max number of args is 6
                        let mut count: [u32; 6] = [0; 6];

                        //validate the args index
                        for arg in args.iter() {
                            if arg.index > 5 {
                                println!(
                                    "invalid seccomp index {} syscall {} args {} ",
                                    arg.index, name, arg.op
                                );
                                return;
                            }
                            count[arg.index as usize] = count[arg.index as usize] + 1;
                            if count[arg.index as usize] > 1 {
                                multiple_args = true;
                                break;
                            }
                        }

                        println!(
                            "the count array {:?}, multiple args {} ",
                            count, multiple_args
                        );

                        //deal
                        let arg_cmp_vec: Vec<seccomp_sys::scmp_arg_cmp> = args
                            .iter()
                            .map(|arg| seccomp_sys::scmp_arg_cmp {
                                arg: arg.index as u32,
                                op: arg.op.to_u32(),
                                datum_a: arg.value,
                                datum_b: arg.value_two,
                            })
                            .collect();

                        //
                        let arg_cnt = arg_cmp_vec.len() as u32;
                        println!(
                            "the arg count {}, has multiple args {}",
                            arg_cnt, multiple_args
                        );

                        println!("*****************");
                        println!("{:?}", arg_cmp_vec);
                        println!("*****************");

                        if !multiple_args {
                            let result = seccomp_rule_add_array(
                                ctx,
                                action.to_u32(),
                                syscall_nbr,
                                arg_cnt,
                                arg_cmp_vec.as_ptr(), //todo
                            );
                            println!("the result of seccomp_rule_add_array {}", result);
                            if result < 0 && result == -libc::EEXIST {
                                println!("failed: seccomp_rule_add_array, result {} ", result);
                                seccomp_release(ctx);
                                return;
                            }
                        } else {
                            for arg in arg_cmp_vec {
                                let result = seccomp_rule_add_array(
                                    ctx,
                                    action.to_u32(),
                                    syscall_nbr,
                                    1,
                                    &arg,
                                );
                                println!("seccomp_rule_add_array result {}", result);
                                if result < 0 && result == -libc::EEXIST {
                                    println!("failed: seccomp_rule_add_array, result {} ", result);
                                    seccomp_release(ctx);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
        let result = seccomp_attr_set(ctx, seccomp_sys::scmp_filter_attr::SCMP_FLTATR_CTL_NNP, 0);
        println!(" result after calling seccomp_attr_set {}", result);
        /*if result < 0  {
            println!(" result is less than 0 ");
            match result.abs() { //lets ignore the negative
                //Setting the attribute with the given value is not allowed.
                libc::EACCES =>


                -EEXIST
                    The attribute does not exist.

                    -EINVAL
                Invalid input, either the context or architecture token is
                    invalid.

                        -EOPNOTSUPP
                The library doesn't support the particular operation.
            }
        }*/

        //load
        println!("loading the seccomp_load");
        let result = seccomp_load(ctx);
        println!("loading result {} ", result);
        //release it
        seccomp_release(ctx);
        println!("done ");
        //seccomp_export_bpf debug
    }
}
