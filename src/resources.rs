use crate::{main, ChildConfig};
use serde::__private::Formatter;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write;
use std::io::Error;
use std::path::Display;
use std::{fmt, fs};

///https://github.com/giuseppe/crun/blob/master/crun.1.md#cgroup-v2
/// https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
///LinuxResources has container runtime resource constraints
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "resources")]
//#[serde(rename_all = "camelCase")]
pub struct LinuxResources {
    /// Memory restriction configuration
    memory: Option<LinuxMemory>,
    /// CPU resource restriction configuration
    cpu: Option<LinuxCPU>,
    ///cpusets restrictions
    cpuSet: Option<LinuxCPUSet>,
    /// Task resource restriction configuration.
    pids: Option<LinuxPids>,
    /// BlockIO restriction configuration
    blockIO: Option<LinuxBlockIO>,
    /// Hugetlb limit (in bytes)
    #[serde(flatten)]
    hugepageLimits: Option<LinuxHugepageLimits>,
    /// Rdma resource restriction configuration.
    /// Limits are a set of key value pairs that define RDMA resource limits,
    /// where the key is device name and value is resource limits.
    /// e.g.
    /// mlx4_0 hca_handle=2 hca_object=2000
    /// ocrdma1 hca_handle=3 hca_object=max
    #[serde(flatten)]
    rdma: Option<LinuxRdma>,
}

/// LinuxRdma for Linux cgroup 'rdma' resource management (Linux 4.11)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxHugepageLimits {
    hugepageLimits: Option<Vec<LinuxHugepageLimit>>,
}

/// LinuxRdma for Linux cgroup 'rdma' resource management (Linux 4.11)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxRdma {
    rdma: Option<Vec<LinuxRdmaEntry>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "rdma")]
#[serde(rename_all = "camelCase")]
struct LinuxRdmaEntry {
    ///device name
    device_name: String,
    /// Maximum number of HCA handles that can be opened. Default is "no limit".
    ///hca_handle
    hca_handle: Option<u32>,
    /// Maximum number of HCA objects that can be created. Default is "no limit".
    /// hca_object
    hca_object: Option<u32>,
}

///ocrdma1 hca_handle=3 hca_object=max
impl fmt::Display for LinuxRdmaEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut buffer = String::new();
        buffer.push_str(&self.device_name);
        match self.hca_handle {
            None => buffer.push_str("\thca_handle=max"),
            Some(hca) => buffer.push_str(&format!("\thca_handle={}", hca)),
        }
        match self.hca_object {
            None => buffer.push_str("\thca_object=max"),
            Some(hca) => buffer.push_str(&format!("\thca_object={}", hca)),
        }
        write!(f, "{}", buffer)
    }
}

/// LinuxMemory for Linux cgroup 'memory' resource management
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "memory")]
#[serde(rename_all = "camelCase")]
pub struct LinuxMemory {
    /// Memory limit (in bytes).
    /// default 0
    /// memory.min
    memory_min: Option<u64>,
    /// Memory reservation or soft_limit (in bytes).
    /// default 0
    /// memory.low
    memory_low: Option<u64>,
    ///default max
    memory_high: Option<u64>,
    /// Memory limit (in bytes).
    /// default max
    /// memory.max
    memory_max: Option<u64>,
    memory_oom_group: Option<u64>,
    /// Total memory limit (memory + swap).
    /// default max
    /// memory.swap.high
    memory_swap_high: Option<u64>,
    /// default max
    /// memory.swap.max
    memory_swap_max: Option<u64>,
}

/// LinuxPids for Linux cgroup 'pids' resource management (Linux 4.3)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "pids")]
#[serde(rename_all = "camelCase")]
pub struct LinuxPids {
    /// Maximum number of PIDs. Default is "no limit".
    /// pids.max
    pids_max: u64,
}

/// LinuxCPU for Linux cgroup 'cpu' resource management
/// All time durations are in microseconds.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "cpu")]
#[serde(rename_all = "camelCase")]
pub struct LinuxCPU {
    /// CPU shares (relative weight (ratio) vs. other cgroups with cpu shares).
    ///The weight in the range [1, 10000].
    /// cpu.weight
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_weight: Option<u64>,

    ///The nice value is in the range [-20, 19].
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_weight_nice: Option<i16>,
    /// Max allowed cpu time in a given period.
    /// default is 'max' indicating no limit
    /// cpu.max
    #[serde(flatten)]
    cpu_max: Option<CpuMax>,
    ///default 0
    cpu_uclamp_min: Option<f32>,
    ///default max
    cpu_uclamp_max: Option<f32>,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "cpu_max")]
#[serde(rename_all = "camelCase")]
struct CpuMax {
    quota: Option<u64>,
    /// CPU period to be used for the quota (in usecs).
    /// default is 100000
    period: Option<u64>,
}

impl fmt::Display for CpuMax {
    ///$MAX $PERIOD
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buffer = String::new();
        match self.quota {
            None => buffer.push_str("max"),
            Some(max) => {
                buffer.push_str(max.to_string().as_str());
                buffer.push_str(" "); //space
                self.period
                    .map(|period| buffer.push_str(period.to_string().as_str()));
            }
        }

        write!(f, "{}", buffer)
    }
}

/// LinuxCPUSet for Linux cgroup 'cpuset' resource management
/// All time durations are in microseconds.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "cpuset")]
#[serde(rename_all = "camelCase")]
pub struct LinuxCPUSet {
    /// CPUs to use within the cpuset. Default is to use any CPU available.
    /// format : 0-4,6,8-10
    /// cpuset.cpus
    cpuset_cpus: Option<String>,
    /// List of memory nodes in the cpuset. Default is to use any available memory node.
    /// Format: 0-1,3
    /// cpuset.mems
    cpuset_mems: Option<String>,

    //todo use enum
    ///cpuset.cpus.partition
    cpuset_cpus_partition: Option<String>,
}

/// LinuxBlockIO for Linux cgroup 'io' resource management
/// todo needs more work, add io.max
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "io")]
#[serde(rename_all = "camelCase")]
pub struct LinuxBlockIO {
    //default weight applied to devices without specific override
    //default 100
    default_weight: Option<u64>,
    /// Weight per cgroup per device
    weight: Option<Vec<LinuxWeightDevice>>,
    /// Specifies per cgroup weight
    /// rbps
    io_limits: Option<Vec<LinuxDeviceEntry>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "device_entry")]
#[serde(rename_all = "camelCase")]
struct LinuxDeviceEntry {
    ///device id in $MAJ:$MIN
    #[serde(flatten)]
    device: LinuxBlockIODevice,
    ///	Max read bytes per second
    rbps: Option<u64>,
    ///Max write bytes per second
    wbps: Option<u64>,
    ///Max read IO operations per second
    riops: Option<u64>,
    ///Max write IO operations per second
    wiops: Option<u64>,
}

///linux device in the format $MAJ:$MIN device numbers
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "device")]
#[serde(rename_all = "camelCase")]
pub struct LinuxBlockIODevice {
    /// Major is the device's major number.
    major: u64,
    /// Minor is the device's minor number.
    minor: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "io")]
#[serde(rename_all = "camelCase")]
struct LinuxWeightDevice {
    ///device id in $MAJ:$MIN
    #[serde(flatten)]
    device: LinuxBlockIODevice,
    /// Weight is the bandwidth rate for the device.
    /// value range [1, 10000]
    /// default 100
    weight: u16,
}

/// LinuxHugepageLimit structure corresponds to limiting kernel hugepages
/// The HugeTLB controller allows to limit the HugeTLB usage per control group and enforces the
/// controller limit during page fault.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "hugepageLimit")]
#[serde(rename_all = "camelCase")]
struct LinuxHugepageLimit {
    /// Pagesize is the hugepage size
    /// Format: "<size><unit-prefix>B' (e.g. 64KB, 2MB, 1GB, etc.)
    huge_page_size: String,
    /// Limit is the limit of "hugepagesize" hugetlb usage
    /// max
    /// hugetlb.<hugepageSize>.max
    max: Option<u64>,
}

// The abstract visitor
pub trait Visitor<T> {
    fn visit_cpu(&mut self, n: &LinuxCPU) -> T;
    fn visit_pids(&mut self, s: &LinuxPids) -> T;
    fn visit_memory(&mut self, e: &LinuxMemory) -> T;
    fn visit_rdma(&mut self, e: &LinuxRdma) -> T;
    fn visit_cpuset(&mut self, e: &LinuxCPUSet) -> T;
    fn visit_io(&mut self, e: &LinuxBlockIO) -> T;
    fn visit_hugepage(&mut self, e: &LinuxHugepageLimits) -> T;
    fn visit_resources(&mut self, e: &LinuxResources) -> T;
}

struct Interpreter<'a> {
    child_directory: &'a str,
}

impl<'a> Interpreter<'a> {
    pub fn new(child_directory: &'a str) -> Self {
        Interpreter { child_directory }
    }
}

impl Visitor<String> for Interpreter<'_> {
    fn visit_cpu(&mut self, n: &LinuxCPU) -> String {
        n.cpu_weight.as_ref().map(|weight| {
            fs::write(
                format!("{}/cpu.weight", self.child_directory),
                weight.to_string(),
            )
        });

        //alternative
        n.cpu_weight_nice.as_ref().map(|weight_nice| {
            fs::write(
                format!("{}/cpu_weight_nice", self.child_directory),
                weight_nice.to_string(),
            )
        });

        n.cpu_max
            .as_ref()
            .map(|max| fs::write(format!("{}/cpu.max", self.child_directory), max.to_string()));

        n.cpu_uclamp_max.as_ref().map(|uclamp_max| {
            fs::write(
                format!("{}/cpu.uclamp.max", self.child_directory),
                uclamp_max.to_string(),
            )
        });

        n.cpu_uclamp_min.as_ref().map(|uclamp_min| {
            fs::write(
                format!("{}/cpu.uclamp.min", self.child_directory),
                uclamp_min.to_string(),
            )
        });

        String::from("done")
    }
    fn visit_pids(&mut self, s: &LinuxPids) -> String {
        fs::write(
            format!("{}/pids.max", self.child_directory),
            s.pids_max.to_string(),
        );

        String::from("+pids")
    }
    fn visit_memory(&mut self, e: &LinuxMemory) -> String {
        e.memory_min.as_ref().map(|min| {
            fs::write(
                format!("{}/memory.min", self.child_directory),
                min.to_string(),
            )
        });

        e.memory_low.as_ref().map(|low| {
            fs::write(
                format!("{}/memory.low", self.child_directory),
                low.to_string(),
            )
        });

        e.memory_high.as_ref().map(|high| {
            fs::write(
                format!("{}/memory.high", self.child_directory),
                high.to_string(),
            )
        });

        e.memory_max.as_ref().map(|max| {
            fs::write(
                format!("{}/memory.max", self.child_directory),
                max.to_string(),
            )
        });

        e.memory_oom_group.as_ref().map(|oom| {
            fs::write(
                format!("{}/memory.oom.group", self.child_directory),
                oom.to_string(),
            )
        });

        e.memory_swap_high.as_ref().map(|swap_high| {
            fs::write(
                format!("{}/memory.swap.high", self.child_directory),
                swap_high.to_string(),
            )
        });

        e.memory_swap_max.as_ref().map(|swap_max| {
            fs::write(
                format!("{}/memory.swap.max", self.child_directory),
                swap_max.to_string(),
            )
        });

        String::from("done")
    }
    fn visit_rdma(&mut self, e: &LinuxRdma) -> String {
        e.rdma.as_ref().map(|rdma_entries| {
            let mut buffer = String::new();
            for rdma_entry in rdma_entries {
                writeln!(&mut buffer, "{}", rdma_entry.to_string());
            }
            fs::write(format!("{}/rdma.max", self.child_directory), buffer)
        });
        String::from("done")
    }

    fn visit_cpuset(&mut self, e: &LinuxCPUSet) -> String {
        e.cpuset_cpus.as_ref().map(|cpus| {
            fs::write(
                format!("{}/cpuset.cpus", self.child_directory),
                cpus.to_string(),
            )
        });

        e.cpuset_mems.as_ref().map(|mems| {
            fs::write(
                format!("{}/cpuset.mems", self.child_directory),
                mems.to_string(),
            )
        });

        String::from("done")
    }

    fn visit_io(&mut self, e: &LinuxBlockIO) -> String {
        let weights = e.weight.as_ref().unwrap();
        //The first line is the default weight applied to devices without specific override.
        // The rest are overrides keyed by $MAJ:$MIN device numbers and not ordered
        //$MAJ:$MIN $WEIGH
        let mut buffer = String::new();
        match e.default_weight {
            None => writeln!(&mut buffer, "{}", "default 100"),
            Some(def) => writeln!(&mut buffer, "default {}", def),
        };
        for weight in weights {
            writeln!(
                &mut buffer,
                "{}:{}\t{}",
                weight.device.major, weight.device.minor, weight.weight
            );
        }
        fs::write(format!("{}/io.weight", self.child_directory), buffer);

        //io.max
        let mut buffer = String::new();
        let io_limits = e.io_limits.as_ref().unwrap();
        for io_limit in io_limits {
            write!(
                &mut buffer,
                "{}:{}\t",
                io_limit.device.major, io_limit.device.minor,
            );
            match io_limit.rbps {
                None => {}
                Some(rbps) => {
                    write!(&mut buffer, "rbps={}\t", rbps);
                }
            };
            match io_limit.wbps {
                None => {}
                Some(wbps) => {
                    write!(&mut buffer, "wbps={}\t", wbps);
                }
            };

            match io_limit.riops {
                None => {}
                Some(riops) => {
                    write!(&mut buffer, "riops={}\t", riops);
                }
            };

            match io_limit.wiops {
                None => {}
                Some(wiops) => {
                    write!(&mut buffer, "wiops={}\t", wiops);
                }
            };
            //end with new line
            writeln!(&mut buffer);
        }
        fs::write(format!("{}/io.max", self.child_directory), buffer);

        //

        String::from("+io")
    }

    ///hugetlb.<hugepagesize>.max
    fn visit_hugepage(&mut self, e: &LinuxHugepageLimits) -> String {
        let hugetlbs = e.hugepageLimits.as_ref().unwrap();

        for hugetlb in hugetlbs {
            match hugetlb.max {
                None => fs::write(
                    format!(
                        "{}/hugetlb.{}.max",
                        self.child_directory, hugetlb.huge_page_size
                    ),
                    "max",
                ),
                Some(htlb) => fs::write(
                    format!(
                        "{}/hugetlb.{}.max",
                        self.child_directory, hugetlb.huge_page_size
                    ),
                    htlb.to_string(),
                ),
            };
        }

        String::from("+io")
    }

    fn visit_resources(&mut self, e: &LinuxResources) -> String {
        &e.cpu.as_ref().map(|cpu| self.visit_cpu(&cpu));
        &e.memory.as_ref().map(|memory| self.visit_memory(&memory));
        &e.pids.as_ref().map(|pids| self.visit_pids(&pids));
        &e.cpuSet.as_ref().map(|cpuset| self.visit_cpuset(&cpuset));
        &e.rdma.as_ref().map(|rdma| self.visit_rdma(&rdma));
        &e.hugepageLimits
            .as_ref()
            .map(|hugetlb| self.visit_hugepage(&hugetlb));
        &e.blockIO.as_ref().map(|io| self.visit_io(&io));
        String::from("")
    }
}

///
struct Validator {}

impl Validator {
    pub fn new() -> Self {
        Validator {}
    }
}

///walk the json tree and validate the values make sense
impl Visitor<String> for Validator {
    fn visit_cpu(&mut self, n: &LinuxCPU) -> String {
        let mut buffer = String::new();
        n.cpu_weight.as_ref().map(|weight| {
            if *weight < 1u64 || *weight > 10000 {
                let msg = format!(
                    "Invalid value for cpu.weight; expected range  [1, 10000], got  {}.",
                    weight
                );
                buffer.push_str(&msg)
            }
        });

        //The nice value should be in the range [-20, 19].
        n.cpu_weight_nice.as_ref().map(|weight_nice| {
            if *weight_nice < -20 || *weight_nice > 19 {
                let msg = format!(
                    "Invalid value for cpu.weight.nice; expected range [-20, 19]., got  {}.",
                    weight_nice
                );
                buffer.push_str(&msg)
            }
        });

        if n.cpu_weight_nice.is_some() && n.cpu_weight.is_some() {
            //both can't be specified at the same time
            let msg = format!("Can't specify both cpu.weight and cpu.weight.nice");
            buffer.push_str(&msg)
        }
        buffer
    }

    fn visit_pids(&mut self, s: &LinuxPids) -> String {
        unimplemented!()
    }

    fn visit_memory(&mut self, e: &LinuxMemory) -> String {
        unimplemented!()
    }

    fn visit_rdma(&mut self, e: &LinuxRdma) -> String {
        unimplemented!()
    }

    fn visit_cpuset(&mut self, e: &LinuxCPUSet) -> String {
        unimplemented!()
    }

    fn visit_io(&mut self, e: &LinuxBlockIO) -> String {
        unimplemented!()
    }

    fn visit_hugepage(&mut self, e: &LinuxHugepageLimits) -> String {
        unimplemented!()
    }

    fn visit_resources(&mut self, e: &LinuxResources) -> String {
        let r = &e.cpu.as_ref().map(|cpu| self.visit_cpu(&cpu));
        println!("{:?}", r);
        String::from("")
    }
}

/*impl fmt::Display for LinuxResources {
    ///write the linux resource in the format:
    /// "+cpu +memory" if the value is present
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut i = Interpreter;
        let int = i.visit_resources(self);
        write!(f, "{}", int)
    }
}*/

impl LinuxResources {
    /// install the resources run the commands
    /// https://lwn.net/Articles/679786/
    /// cgroup_path =/sys/fs/cgroup
    pub fn install_resources(
        resources: &LinuxResources,
        config: &ChildConfig,
        cgroup_path: &str,
    ) -> std::io::Result<()> {
        //cpuset cpu io memory hugetlb pids
        let cgroup_subsystems = vec![
            "cpuset", "cpu", "rdma", "pids", "memory", "freezer", "io", "hugetlb",
        ];

        eprintln!("settings the cgroups...");

        //todo mount -t cgroup2 none $MOUNT_POINT, cgroup root object iwll be created at /sys/fs/cgroup2
        //after creating, the cgroup.subtree_control inside the /sys/fs/cgroup2 is empty,
        // we now enable the controllers:
        // echo "+memory" > /sys/fs/cgroup2/cgroup.subtree_control
        let parent_subtree_control = format!("{}/cgroup.subtree_control", cgroup_path);
        let res = LinuxResources::enable_controllers(&resources, &parent_subtree_control);
        match res {
            Ok(_) => {
                println!("installed controllers")
            }
            Err(_) => {
                println!("error installation controllers")
            }
        }

        //mkdir /cgroup/group1
        let child_directory = format!("{}/{}", cgroup_path, config.host_name);
        println!("new group {}", child_directory);
        let child_d = fs::create_dir(&child_directory);

        match child_d {
            Ok(_) => {
                println!("created the child directory ")
            }
            Err(_) => {
                println!("error created the child directory ")
            }
        }
        //write the controller resource limits values into the /sys/fs/cgroup/{child}/ directory
        let mut i = Interpreter::new(&child_directory);
        let res = i.visit_resources(resources);
        println!("visited resources {} ", res);

        // format!("{}/memory.max", child_directory),
        Ok(())

        /*let pids = &resources
            .pids
            .as_ref()
            .map(|pid| pid.pids_max)
            .map(|lim| format!("pids.max={}", lim));
        println!("{:?}", pids);*/
    }

    ///enable the controllers present in the resource in the parent subtree_control_path
    fn enable_controllers(
        resources: &LinuxResources,
        subtree_control_path: &str,
    ) -> std::io::Result<()> {
        /* let controllers = format!(
            "{} {} {} {} {} {} {} ",
            "+cpu", "+io", "+memory", "+pids", "+cpuset", "+hugetlb", "+rdma",
        );*/
        let mut buffer = String::new();
        match &resources.memory {
            None => {}
            Some(m) => buffer.push_str("+memory"),
        }
        match &resources.cpu {
            None => {}
            Some(cpu) => buffer.push_str(" +cpu"),
        }
        match &resources.cpuSet {
            None => {}
            Some(cpuset) => buffer.push_str(" +cpuset"),
        }

        match &resources.pids {
            None => {}
            Some(pids) => buffer.push_str(" +pids"),
        }

        match &resources.hugepageLimits {
            None => {}
            Some(hugetlb) => buffer.push_str(" +hugetlb"),
        }

        match &resources.hugepageLimits {
            None => {}
            Some(rdma) => buffer.push_str(" +rdma"),
        }

        fs::write(subtree_control_path, buffer.as_str())
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

        let json = r#"{
   "memory":{
      "memoryMin":1000,
      "memoryLow":1000,
      "memoryHigh":536870912,
      "memoryMax":536870912,
      "memoryOomGroup":1,
      "memorySwapHigh":536870912,
      "memorySwapMax":536870912
   },
   "cpu":{
      "cpuWeight":1024,
      "quota":10,
      "period":10000,
      "cpuUclampMin":2.0,
      "cpuUclampMax":3.0
   },
   "cpuSet":{
      "cpusetCpus":"2-3",
      "cpusetMems":"0-7",
      "cpusetCpusPartition":null
   },
   "pids":{
      "pidsMax":32771
   },
   "blockIO":{
      "defaultWeight":200,
      "weight":[
         {
            "major":8,
            "minor":0,
            "weight":500
         },
         {
            "major":8,
            "minor":16,
            "weight":500
         }
      ],
      "ioLimits":[
        {
           "major":8,
           "minor":0,
           "rbps":600
        },
        {
           "major":8,
           "minor":16,
           "wbps":300,
           "riops":400,
           "wiops":600
        }
     ]
   },
   "hugepageLimits":[
      {
         "hugePageSize":"2MB",
         "max":9223372036854772000
      },
      {
         "hugePageSize":"64KB",
         "max":1000000
      }
   ],
   "rdma":[
      {
         "deviceName":"mlx4_0",
         "hcaHandle":2,
         "hcaObject":2000
      },
      {
         "deviceName":"ocrdma1",
         "hcaHandle":3,
         "hcaObject":null
      }
   ]
}"#;
        let mut deserialized: LinuxResources = serde_json::from_str(&json).unwrap();

        let mut rdmas = Vec::new();
        //mlx4_0 hca_handle=2 hca_object=2000
        //ocrdma1 hca_handle=3 hca_object=max
        rdmas.push(LinuxRdmaEntry {
            device_name: String::from("mlx4_0"),
            hca_handle: Some(2),
            hca_object: Some(2000),
        });

        rdmas.push(LinuxRdmaEntry {
            device_name: String::from("ocrdma1"),
            hca_handle: Some(3),
            hca_object: None,
        });

        deserialized.rdma = Some(LinuxRdma { rdma: Some(rdmas) });

        let mut hugepageLimits = Vec::new();
        hugepageLimits.push(LinuxHugepageLimit {
            huge_page_size: String::from("2MB"),
            max: Some(9223372036854772000),
        });

        hugepageLimits.push(LinuxHugepageLimit {
            huge_page_size: "64KB".to_string(),
            max: Some(1000000),
        });

        deserialized.hugepageLimits = Some(LinuxHugepageLimits {
            hugepageLimits: Some(hugepageLimits),
        });

        let mut v = Validator::new();
        let p = v.visit_resources(&deserialized);
        println!("{}", p);

        let serialized = serde_json::to_string(&deserialized).unwrap();
        println!("serialized = {}", serialized);
        //println!("deserialized = {:?}", deserialized);
        let child_confg = ChildConfig {
            argc: 0,
            uid: Uid::from_raw(12),
            fd: 0,
            host_name: "test_host",
            argv: vec![],
            mount_dir: "",
        };
        let res = LinuxResources::install_resources(
            &deserialized,
            &child_confg,
            "/Users/rmokua/Dev/rust/containers/crust",
        );
    }
}
