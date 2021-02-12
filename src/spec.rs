use crate::resources::LinuxResources;

use seccomp_sys::scmp_compare;
use seccomp_sys::scmp_compare::SCMP_CMP_NE;
use serde::__private::Formatter;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;

/// base config for the container
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "spec")]
//#[serde(rename_all = "camelCase")]
pub struct Spec {
    // Process configures the container process.
    pub(crate) process: Option<Process>,
    // Root configures the container's root filesystem.
    pub(crate) root: Option<Root>,
    // Hostname configures the container's hostname.
    pub(crate) hostname: String,
    // Mounts configures additional mounts (on top of Root).
    pub(crate) mounts: Option<Vec<Mount>>,
    // Linux is platform-specific configuration for Linux based containers.
    //#[cfg(any(target_os = "linux"))]
    pub(crate) linux: Option<Linux>,
}

/// Process contains information to start a specific application inside the container.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "process")]
//#[serde(rename_all = "camelCase")]
pub struct Process {
    // Terminal creates an interactive terminal for the container.
    pub(crate) terminal: Option<bool>,
    // ConsoleSize specifies the size of the console.
    pub(crate) console_size: Option<ConsoleBox>,
    // User specifies user information for the process.
    #[serde(rename = "user")]
    pub(crate) user: User,
    // Args specifies the binary and arguments for the application to execute.
    pub(crate) args: Option<Vec<String>>,
    // Env populates the process environment for the process.
    pub(crate) env: Option<Vec<String>>,
    // Cwd is the current working directory for the process and must be
    // relative to the container's root.
    pub(crate) cwd: String,
    // Capabilities are Linux capabilities that are kept for the process.
    pub(crate) capabilities: Option<LinuxCapabilities>,
    // Rlimits specifies rlimit options to apply to the process.
    pub(crate) rlimits: Option<Vec<POSIXRlimit>>,
    // NoNewPrivileges controls whether additional privileges could be gained by processes in the container.
    #[serde(rename = "noNewPrivileges")]
    pub(crate) no_new_privileges: Option<bool>,
    // ApparmorProfile specifies the apparmor profile for the container.
    #[serde(rename = "apparmor_profile")]
    pub(crate) apparmor_profile: Option<String>,
    // Specify an oom_score_adj for the container.
    #[serde(rename = "oomScoreAdj")]
    pub(crate) oo_mscore_adj: Option<u32>,
    // SelinuxLabel specifies the selinux context that the container process is run as.
    #[serde(rename = "selinuxLabel")]
    pub(crate) selinux_label: Option<String>,
}

/// Root contains information about the container's root filesystem on the host.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "root")]
//#[serde(rename_all = "camelCase")]
pub struct Root {
    // Path is the absolute path to the container's root filesystem.
    path: String,
    // Readonly makes the root filesystem for the container readonly before the process is executed.
    readonly: Option<bool>,
}

/// Mount specifies a mount for a container.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "mount")]
//#[serde(rename_all = "camelCase")]
pub struct Mount {
    // Destination is the absolute path where the mount will be placed in the container.
    destination: String,
    // Type specifies the mount kind.
    #[serde(rename = "type")]
    mount_type: Option<String>,
    // Source specifies the source path of the mount.
    source: Option<String>,
    // Options are fstab style mount options.
    #[serde(rename = "options")]
    mount_options: Option<Vec<String>>,
}

/// Linux contains platform-specific configuration for Linux based containers.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "linux")]
//#[serde(rename_all = "camelCase")]
pub struct Linux {
    // UIDMapping specifies user mappings for supporting user namespaces.
    #[serde(rename = "uidMappings")]
    pub(crate) uidmappings: Option<Vec<LinuxIDMapping>>,
    // GIDMapping specifies group mappings for supporting user namespaces.
    #[serde(rename = "gidMappings")]
    pub(crate) gidmappings: Option<Vec<LinuxIDMapping>>,
    // sysctl are a set of key value pairs that are set for the container on start
    #[serde(rename = "sysctl")]
    pub(crate) sysctl: Option<HashMap<String, String>>,
    // Resources contain cgroup information for handling resource constraints
    // for the container
    pub(crate) resources: Option<LinuxResources>,
    // cgroups_path specifies the path to cgroups that are created and/or joined by the container.
    // The path is expected to be relative to the cgroups mountpoint.
    // If resources are specified, the cgroups at cgroups_path will be updated based on resources.
    #[serde(rename = "cgroupsPath")]
    pub(crate) cgroups_path: Option<String>,
    // Namespaces contains the namespaces that are created and/or joined by the container
    pub(crate) namespaces: Option<Vec<LinuxNamespace>>,
    // Devices are a list of device nodes that are created for the container
    pub(crate) devices: Option<Vec<LinuxDevice>>,
    // Seccomp specifies the seccomp security settings for the container.
    pub seccomp: Option<LinuxSeccomp>,
    // RootfsPropagation is the rootfs mount propagation mode for the container.
    #[serde(rename = "rootfsPropagation")]
    pub(crate) rootfs_propagation: Option<String>,
    // MaskedPaths masks over the provided paths inside the container.
    #[serde(rename = "maskedPaths")]
    pub(crate) masked_paths: Option<Vec<String>>,
    // ReadonlyPaths sets the provided paths as RO inside the container.
    #[serde(rename = "readonlyPaths")]
    pub(crate) readonly_paths: Option<Vec<String>>,
    // MountLabel specifies the selinux context for the mounts in the container.
    #[serde(rename = "mountLabel")]
    pub(crate) mount_label: Option<String>,
    // IntelRdt contains Intel Resource Director Technology (RDT) information for
    // handling resource constraints (e.g., L3 cache, memory bandwidth) for the container
    //intelRdt: Option<LinuxIntelRdt>,
    // Personality contains configuration for the Linux personality syscall
    pub(crate) personality: Option<LinuxPersonality>,
}

// Box specifies dimensions of a rectangle. Used for specifying the size of a console.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "consoleBox")]
#[serde(rename_all = "camelCase")]
pub struct ConsoleBox {
    // Height is the vertical dimension of a box.
    height: usize,
    // Width is the horizontal dimension of a box.
    width: usize,
}

/// User specifies specific user (and group) information for the container process.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "user")]
//#[serde(rename_all = "camelCase")]
pub struct User {
    // uid is the user id.
    uid: u32,
    // gid is the group id.
    gid: u32,
    // umask is the umask for the init process.
    umask: Option<u32>,
    // additional_gids are additional group ids set for the container's process.
    #[serde(rename = "additionalGids")]
    additional_gids: Option<Vec<u32>>,
}

/// LinuxCapabilities specifies the list of allowed capabilities that are kept for a process.
/// http://man7.org/linux/man-pages/man7/capabilities.7.html
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "capabilities")]
pub struct LinuxCapabilities {
    // Bounding is the set of capabilities checked by the kernel.
    pub(crate) bounding: Option<Vec<String>>,
    // Effective is the set of capabilities checked by the kernel.
    pub(crate) effective: Option<Vec<String>>,
    // Inheritable is the capabilities preserved across execve.
    pub(crate) inheritable: Option<Vec<String>>,
    // Permitted is the limiting superset for effective capabilities.
    pub(crate) permitted: Option<Vec<String>>,
    // ambient is the ambient set of capabilities that are kept.
    pub(crate) ambient: Option<Vec<String>>,
}

impl Display for LinuxCapabilities {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let buffer = String::new();
        writeln!(f,"bounding = {:?}, effective = {:?}, inheritable = {:?}, permitted = {:?}, ambient = {:?}", self.bounding,self.effective, self.inheritable,self.permitted,self.ambient)
    }
}

/// POSIXRlimit type and restrictions
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "rlimit")]
pub struct POSIXRlimit {
    // Type of the rlimit to set
    #[serde(rename = "type")]
    rlimit_type: String,
    // Hard is the hard limit for the specified type
    hard: u64,
    // Soft is the soft limit for the specified type
    soft: u64,
}

/// LinuxIDMapping specifies uid/gid mappings
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "uidMappings")]
pub struct LinuxIDMapping {
    // container_id is the starting uid/gid in the container
    #[serde(rename = "containerID")]
    container_id: u32,
    // HostID is the starting uid/gid on the host to be mapped to 'container_id'
    #[serde(rename = "hostID")]
    host_id: u32,
    // Size is the number of IDs to be mapped
    size: u32,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "namespace")]
pub struct LinuxNamespace {
    // Type is the type of namespace
    #[serde(rename = "type")]
    namespace_type: LinuxNamespaceType,
    // Path is a path to an existing namespace persisted on disk that can be joined
    // and is of the same type
    path: Option<String>,
}

// LinuxNamespaceType is one of the Linux namespaces
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "namespace")]
pub enum LinuxNamespaceType {
    #[serde(rename = "pid")]
    Pid,
    #[serde(rename = "network")]
    Network,
    #[serde(rename = "mount")]
    Mount,
    #[serde(rename = "ipc")]
    IPC,
    #[serde(rename = "uts")]
    UTS,
    #[serde(rename = "user")]
    User,
    #[serde(rename = "cgroup")]
    CGroup,
}

impl fmt::Display for LinuxNamespaceType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            // PIDNamespace for isolating process IDs
            LinuxNamespaceType::Pid => {
                write!(f, "pid")
            }
            // NetworkNamespace for isolating network devices, stacks, ports, etc
            LinuxNamespaceType::Network => {
                write!(f, "network")
            }
            // MountNamespace for isolating mount points
            LinuxNamespaceType::Mount => {
                write!(f, "mount")
            }
            // IPCNamespace for isolating System V IPC, POSIX message queues
            LinuxNamespaceType::IPC => {
                write!(f, "ipc")
            }
            // UTSNamespace for isolating hostname and NIS domain name
            LinuxNamespaceType::UTS => {
                write!(f, "uts")
            }
            // UserNamespace for isolating user and group IDs
            LinuxNamespaceType::User => {
                write!(f, "user")
            }
            // CgroupNamespace for isolating cgroup hierarchies
            LinuxNamespaceType::CGroup => {
                write!(f, "cgroup")
            }
        }
    }
}

/// LinuxDevice represents the mknod information for a Linux special device file
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "device")]
pub struct LinuxDevice {
    // Path to the device.
    path: String,
    // Device type, block, char, etc.
    #[serde(rename = "type")]
    device_type: String,
    // Major is the device's major number.
    major: i64,
    // Minor is the device's minor number.
    minor: i64,
    // FileMode permission bits for the device.
    #[serde(rename = "fileMode")]
    file_mode: Option<u32>, //Option<FileMode>,
    // uid of the device.
    #[serde(rename = "uid")]
    uid: Option<u32>,
    // Gid of the device.
    #[serde(rename = "gid")]
    gid: Option<u32>,
}

// LinuxSeccomp represents syscall restrictions
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "seccomp")]
#[serde(rename_all = "camelCase")]
pub struct LinuxSeccomp {
    #[serde(rename = "defaultAction")]
    pub(crate) default_action: LinuxSeccompAction,
    pub(crate) architectures: Option<Vec<Arch>>,
    pub(crate) flags: Option<Vec<LinuxSeccompFlag>>,
    pub(crate) syscalls: Option<Vec<LinuxSyscall>>,
}

// Arch used for additional architectures
//type Arch = String;

// LinuxSeccompFlag is a flag to pass to seccomp(2).
type LinuxSeccompFlag = String;

// Additional architectures permitted to be used for system calls
// By default only the native architecture of the kernel is permitted
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "architecture")]
pub enum Arch {
    #[serde(rename = "SCMP_ARCH_X86")]
    ArchX86,
    ArchX86_64,
    #[serde(rename = "SCMP_ARCH_X32")]
    ArchX32,
    ArchARM,
    ArchAARCH64,
    ArchMIPS,
    ArchMIPS64,
    ArchMIPS64N32,
    ArchMIPSEL,
    ArchMIPSEL64,
    ArchMIPSEL64N32,
    ArchPPC,
    ArchPPC64,
    ArchPPC64LE,
    ArchS390,
    ArchS390X,
    ArchPARISC,
    ArchPARISC64,
    ArchRISCV64,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Arch::ArchX86 => {
                write!(f, "SCMP_ARCH_X86")
            }
            Arch::ArchX86_64 => {
                write!(f, "SCMP_ARCH_X86_64")
            }
            Arch::ArchX32 => {
                write!(f, "SCMP_ARCH_X32")
            }
            Arch::ArchARM => {
                write!(f, "SCMP_ARCH_ARM")
            }
            Arch::ArchAARCH64 => {
                write!(f, "SCMP_ARCH_AARCH64")
            }
            Arch::ArchMIPS => {
                write!(f, "SCMP_ARCH_MIPS")
            }
            Arch::ArchMIPS64 => {
                write!(f, "SCMP_ARCH_MIPS64")
            }
            Arch::ArchMIPS64N32 => {
                write!(f, "SCMP_ARCH_MIPS64N32")
            }
            Arch::ArchMIPSEL => {
                write!(f, "SCMP_ARCH_MIPSEL")
            }
            Arch::ArchMIPSEL64 => {
                write!(f, "SCMP_ARCH_MIPSEL64")
            }
            Arch::ArchMIPSEL64N32 => {
                write!(f, "SCMP_ARCH_MIPSEL64N32")
            }
            Arch::ArchPPC => {
                write!(f, "SCMP_ARCH_PPC")
            }
            Arch::ArchPPC64 => {
                write!(f, "SCMP_ARCH_PPC64")
            }
            Arch::ArchPPC64LE => {
                write!(f, "SCMP_ARCH_PPC64LE")
            }
            Arch::ArchS390 => {
                write!(f, "SCMP_ARCH_S390")
            }
            Arch::ArchS390X => {
                write!(f, "SCMP_ARCH_S390X")
            }
            Arch::ArchPARISC => {
                write!(f, "SCMP_ARCH_PARISC")
            }
            Arch::ArchPARISC64 => {
                write!(f, "SCMP_ARCH_PARISC64")
            }
            Arch::ArchRISCV64 => {
                write!(f, "SCMP_ARCH_RISCV64")
            }
        }
    }
}

// LinuxSeccompAction taken upon Seccomp rule match
// Define actions for Seccomp rules
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "seccompAction")]
pub enum LinuxSeccompAction {
    #[serde(rename = "SCMP_ACT_KILL")]
    ActKill,
    #[serde(rename = "SCMP_ACT_KILL_PROCESS")]
    ActKillProcess,
    #[serde(rename = "SCMP_ACT_KILL_THREAD")]
    ActKillThread,
    #[serde(rename = "SCMP_ACT_TRAP")]
    ActTrap,
    #[serde(rename = "SCMP_ACT_ERRNO")]
    ActErrno,
    #[serde(rename = "SCMP_ACT_TRACE")]
    ActTrace,
    #[serde(rename = "SCMP_ACT_ALLOW")]
    ActAllow,
    #[serde(rename = "SCMP_ACT_LOG")]
    ActLog,
}

impl LinuxSeccompAction {
    pub fn to_u32(&self) -> u32 {
        match self {
            //SCMP_ACT_KILL
            LinuxSeccompAction::ActKill => seccomp_sys::SCMP_ACT_KILL,
            //SCMP_ACT_KILL_PROCESS
            LinuxSeccompAction::ActKillProcess => seccomp_sys::SCMP_ACT_KILL_PROCESS,
            //SCMP_ACT_TRAP
            LinuxSeccompAction::ActKillThread => seccomp_sys::SCMP_ACT_KILL_PROCESS,
            //SCMP_ACT_ERRNO
            LinuxSeccompAction::ActTrap => seccomp_sys::SCMP_ACT_TRAP,
            LinuxSeccompAction::ActErrno => seccomp_sys::SCMP_ACT_ERRNO(0),
            LinuxSeccompAction::ActTrace => seccomp_sys::SCMP_ACT_TRACE(0),
            LinuxSeccompAction::ActAllow => seccomp_sys::SCMP_ACT_ALLOW,
            LinuxSeccompAction::ActLog => seccomp_sys::SCMP_ACT_ALLOW, //todo
        }
    }
}

impl fmt::Display for LinuxSeccompAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            LinuxSeccompAction::ActKill => {
                write!(f, "SCMP_ACT_KILL")
            }
            LinuxSeccompAction::ActKillProcess => {
                write!(f, "SCMP_ACT_KILL_PROCESS")
            }
            LinuxSeccompAction::ActKillThread => {
                write!(f, "SCMP_ACT_KILL_THREAD")
            }
            LinuxSeccompAction::ActTrap => {
                write!(f, "SCMP_ACT_TRAP")
            }
            LinuxSeccompAction::ActErrno => {
                write!(f, "SCMP_ACT_ERRNO")
            }
            LinuxSeccompAction::ActTrace => {
                write!(f, "SCMP_ACT_TRACE")
            }
            LinuxSeccompAction::ActAllow => {
                write!(f, "SCMP_ACT_ALLOW")
            }
            LinuxSeccompAction::ActLog => {
                write!(f, "SCMP_ACT_LOG")
            }
        }
    }
}

// LinuxSeccompOperator used to match syscall arguments in Seccomp
// Define operators for syscall arguments in Seccomp
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "operator")]
pub enum LinuxSeccompOperator {
    #[serde(rename = "SCMP_CMP_NE")]
    OpNotEqual,
    #[serde(rename = "SCMP_CMP_LT")]
    OpLessThan,
    #[serde(rename = "SCMP_CMP_LE")]
    OpLessEqual,
    #[serde(rename = "SCMP_CMP_EQ")]
    OpEqualTo,
    #[serde(rename = "SCMP_CMP_GE")]
    OpGreaterEqual,
    #[serde(rename = "SCMP_CMP_GT")]
    OpGreaterThan,
    #[serde(rename = "SCMP_CMP_MASKED_EQ")]
    OpMaskedEqual,
}

impl LinuxSeccompOperator {
    pub fn to_u32(&self) -> seccomp_sys::scmp_compare {
        match self {
            LinuxSeccompOperator::OpNotEqual => seccomp_sys::scmp_compare::SCMP_CMP_NE,
            LinuxSeccompOperator::OpLessThan => seccomp_sys::scmp_compare::SCMP_CMP_LT,
            LinuxSeccompOperator::OpLessEqual => seccomp_sys::scmp_compare::SCMP_CMP_LE,
            LinuxSeccompOperator::OpEqualTo => seccomp_sys::scmp_compare::SCMP_CMP_EQ,
            LinuxSeccompOperator::OpGreaterEqual => seccomp_sys::scmp_compare::SCMP_CMP_GE,
            LinuxSeccompOperator::OpGreaterThan => seccomp_sys::scmp_compare::SCMP_CMP_GT,
            LinuxSeccompOperator::OpMaskedEqual => seccomp_sys::scmp_compare::SCMP_CMP_MASKED_EQ,
        }
    }
}

impl fmt::Display for LinuxSeccompOperator {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            LinuxSeccompOperator::OpNotEqual => {
                write!(f, "SCMP_CMP_NE")
            }
            LinuxSeccompOperator::OpLessThan => {
                write!(f, "SCMP_CMP_LT")
            }
            LinuxSeccompOperator::OpLessEqual => {
                write!(f, "SCMP_CMP_LE")
            }
            LinuxSeccompOperator::OpEqualTo => {
                write!(f, "SCMP_CMP_EQ")
            }
            LinuxSeccompOperator::OpGreaterEqual => {
                write!(f, "SCMP_CMP_GE")
            }
            LinuxSeccompOperator::OpGreaterThan => {
                write!(f, "SCMP_CMP_GT")
            }
            LinuxSeccompOperator::OpMaskedEqual => {
                write!(f, "SCMP_CMP_MASKED_EQ")
            }
        }
    }
}

// LinuxSeccompArg used for matching specific syscall arguments in Seccomp
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "arg")]
pub struct LinuxSeccompArg {
    pub index: u32,
    pub value: u64,
    #[serde(rename = "valueTwo")]
    pub value_two: u64,
    pub op: LinuxSeccompOperator,
}

// LinuxSyscall is used to match a syscall in Seccomp
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "syscall")]
pub struct LinuxSyscall {
    pub names: Vec<String>,
    #[serde(rename = "action")]
    pub action: LinuxSeccompAction,
    #[serde(rename = "errnoRet")]
    pub errno_ret: Option<i32>,
    #[serde(rename = "args")]
    pub args: Option<Vec<LinuxSeccompArg>>,
}

// LinuxPersonality represents the Linux personality syscall input
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "linuxPersonality")]
pub struct LinuxPersonality {
    // Domain for the personality
    #[serde(rename = "domain")]
    domain: LinuxPersonalityDomain,
    // Additional flags
    //Flags []LinuxPersonalityFlag `json:"flags,omitempty"`
}

// Define domain and flags for Personality
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "personalityDomain")]
pub enum LinuxPersonalityDomain {
    // PerLinux is the standard Linux personality
    PerLinux,
    // PerLinux32 sets personality to 32 bit
    PerLinux32,
}

impl fmt::Display for LinuxPersonalityDomain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            LinuxPersonalityDomain::PerLinux => {
                write!(f, "LINUX")
            }

            LinuxPersonalityDomain::PerLinux32 => {
                write!(f, "LINUX32")
            }
        }
    }
}
#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use nix::unistd::Uid;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_json() {
        //println!("{}", json);
        let spec = Spec {
            process: Some(Process {
                terminal: None,
                console_size: None,
                user: User {
                    uid: 0,
                    gid: 0,
                    umask: None,
                    additional_gids: None,
                },
                args: None,
                env: None,
                cwd: "".to_string(),
                capabilities: None,
                rlimits: None,
                no_new_privileges: None,
                apparmor_profile: None,
                oo_mscore_adj: None,
                selinux_label: None,
            }),
            root: None,
            hostname: "".to_string(),
            mounts: None,
            linux: Some(Linux {
                uidmappings: None,
                gidmappings: None,
                sysctl: None,
                resources: None,
                cgroups_path: None,
                namespaces: None,
                devices: None,
                seccomp: Some(LinuxSeccomp {
                    default_action: LinuxSeccompAction::ActKill,
                    architectures: Some(vec![Arch::ArchAARCH64, Arch::ArchARM]),
                    flags: None,
                    syscalls: None,
                }),
                rootfs_propagation: None,
                masked_paths: None,
                readonly_paths: None,
                mount_label: None,
                personality: None,
            }),
        };
        let json = serde_json::to_string(&spec).unwrap();
        println!("{}", json);

        let jj = r#"
        {
   "process":{
      "terminal":true,
      "console_size":null,
      "user":{
         "uid":1,
         "gid":1,
         "umask":null,
         "additionalGids":[
            5,
            6
         ]
      },
      "args":[
         "sh"
      ],
      "env":[
         "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
         "TERM=xterm"
      ],
      "cwd":"/",
      "capabilities":{
         "bounding":[
            "CAP_AUDIT_WRITE",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE"
         ],
         "effective":[
            "CAP_AUDIT_WRITE",
            "CAP_KILL"
         ],
         "inheritable":[
            "CAP_AUDIT_WRITE",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE"
         ],
         "permitted":[
            "CAP_AUDIT_WRITE",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE"
         ],
         "ambient":[
            "CAP_NET_BIND_SERVICE"
         ]
      },
      "rlimits":[
         {
            "type":"RLIMIT_CORE",
            "hard":1024,
            "soft":1024
         },
         {
            "type":"RLIMIT_NOFILE",
            "hard":1024,
            "soft":1024
         }
      ],
      "noNewPrivileges":true,
      "apparmor_profile":"acme_secure_profile",
      "oomScoreAdj":100,
      "selinuxLabel":"system_u:system_r:svirt_lxc_net_t:s0:c124,c675"
   },
   "root":{
      "path":"rootfs",
      "readonly":true
   },
   "hostname":"slartibartfast",
   "mounts":[
      {
         "destination":"/proc",
         "type":"proc",
         "source":"proc",
         "options":null
      },
      {
         "destination":"/dev",
         "type":"tmpfs",
         "source":"tmpfs",
         "options":[
            "nosuid",
            "strictatime",
            "mode=755",
            "size=65536k"
         ]
      },
      {
         "destination":"/dev/pts",
         "type":"devpts",
         "source":"devpts",
         "options":[
            "nosuid",
            "noexec",
            "newinstance",
            "ptmxmode=0666",
            "mode=0620",
            "gid=5"
         ]
      },
      {
         "destination":"/dev/shm",
         "type":"tmpfs",
         "source":"shm",
         "options":[
            "nosuid",
            "noexec",
            "nodev",
            "mode=1777",
            "size=65536k"
         ]
      },
      {
         "destination":"/dev/mqueue",
         "type":"mqueue",
         "source":"mqueue",
         "options":[
            "nosuid",
            "noexec",
            "nodev"
         ]
      },
      {
         "destination":"/sys",
         "type":"sysfs",
         "source":"sysfs",
         "options":[
            "nosuid",
            "noexec",
            "nodev"
         ]
      },
      {
         "destination":"/sys/fs/cgroup",
         "type":"cgroup",
         "source":"cgroup",
         "options":[
            "nosuid",
            "noexec",
            "nodev",
            "relatime",
            "ro"
         ]
      }
   ],
   "linux":{
      "uidMappings":[
         {
            "containerID":0,
            "hostID":1000,
            "size":32000
         }
      ],
      "gidMappings":[
         {
            "containerID":0,
            "hostID":1000,
            "size":32000
         }
      ],
      "sysctl":{
         "net.ipv4.ip_forward":"1",
         "net.core.somaxconn":"256"
      },
      "resources":null,
      "cgroupsPath":"/myRuntime/myContainer",
      "namespaces":[
         {
            "type":"pid",
            "path":null
         },
         {
            "type":"network",
            "path":null
         },
         {
            "type":"ipc",
            "path":null
         },
         {
            "type":"uts",
            "path":null
         },
         {
            "type":"mount",
            "path":null
         },
         {
            "type":"user",
            "path":null
         },
         {
            "type":"cgroup",
            "path":null
         }
      ],
      "devices":[
         {
            "path":"/dev/fuse",
            "type":"c",
            "major":10,
            "minor":229,
            "fileMode":438,
            "uid":0,
            "gid":0
         },
         {
            "path":"/dev/sda",
            "type":"b",
            "major":8,
            "minor":0,
            "fileMode":432,
            "uid":0,
            "gid":0
         }
      ],
      "seccomp":{
         "defaultAction":"SCMP_ACT_ALLOW",
         "architectures":[
            "SCMP_ARCH_X86",
            "SCMP_ARCH_X32"
         ],
         "flags":null,
         "syscalls":[
            {
               "names":[
                  "getcwd",
                  "chmod"
               ],
               "action":"SCMP_ACT_ERRNO",
               "errnoRet":null,
               "args":null
            },
            {
               "names":[
                  "clone"
               ],
               "action":"SCMP_ACT_ERRNO",
               "args":[
                  {
                     "index":0,
                     "value":131072,
                     "valueTwo":131072,
                     "op":"SCMP_CMP_MASKED_EQ"
                  },
                  {
                     "index":0,
                     "value":67108864,
                     "valueTwo":67108864,
                     "op":"SCMP_CMP_MASKED_EQ"
                  },
                  {
                     "index":0,
                     "value":134217728,
                     "valueTwo":134217728,
                     "op":"SCMP_CMP_MASKED_EQ"
                  },
                  {
                     "index":0,
                     "value":268435456,
                     "valueTwo":268435456,
                     "op":"SCMP_CMP_MASKED_EQ"
                  },
                  {
                     "index":0,
                     "value":536870912,
                     "valueTwo":536870912,
                     "op":"SCMP_CMP_MASKED_EQ"
                  },
                  {
                     "index":0,
                     "value":1073741824,
                     "valueTwo":1073741824,
                     "op":"SCMP_CMP_MASKED_EQ"
                  }
               ]
            }
         ]
      },
      "rootfsPropagation":"slave",
      "maskedPaths":[
         "/proc/kcore",
         "/proc/latency_stats",
         "/proc/timer_stats",
         "/proc/sched_debug"
      ],
      "readonlyPaths":[
         "/proc/asound",
         "/proc/bus",
         "/proc/fs",
         "/proc/irq",
         "/proc/sys",
         "/proc/sysrq-trigger"
      ],
      "mountLabel":"system_u:object_r:svirt_sandbox_file_t:s0:c715,c811",
      "personality":null
   }
}
      "#;

        let mut spec: Spec = serde_json::from_str(&jj).unwrap();

        println!("the spec {:?} ", spec);

        let ss = serde_json::to_string(&spec).unwrap();
        println!("*************");
        println!("{}", ss);
    }
}
