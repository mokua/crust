use crate::spec::LinuxCapabilities;

use caps::errors::CapsError;
use caps::{Capability, CapsHashSet};
use libc::prctl;
use std::collections::HashSet;
use std::io::Error;
use std::str::FromStr;

impl LinuxCapabilities {
    ///convert the string to a capability
    //pub fn str_to_cap(input: &str) -> Capability {}
    ///convert the vector of strings into a hashset Capability, incase of error, return empty
    pub fn to_linux_cap(input_str: &Vec<String>) -> CapsHashSet {
        //std::collections::HashSet<Capability>
        let mut res: HashSet<Capability> = HashSet::new();
        for input in input_str {
            println!("convert the string : {} ", input);
            match Capability::from_str(&input.to_uppercase()) {
                Err(_) => {
                    println!("error converting cap string to Capability {}", input);
                    return HashSet::new();
                }
                Ok(item) => {
                    println!(
                        "the result of converting, adding to vector the cap {} ",
                        item
                    );
                    res.insert(item);
                }
            }
        }
        res
    }
}

//return Result<i32, String>??
pub fn install_caps(new_caps: &LinuxCapabilities) {
    let current_caps = caps::runtime::procfs_all_supported(None)
        .unwrap_or_else(|_| caps::runtime::thread_all_supported());

    //1.get currents caps
    println!("current capabilities {:?}", current_caps);
    println!("input caps  {:?}", new_caps);

    //1. drop/reset all the caps
    //caps::current_caps.reset_all(); TODO
    //println!("the current caps after resetting {}", current_caps);
    //2. drop all bounding caps not in the config.json file bound set
    let current_bounding_set = caps::read(None, caps::CapSet::Bounding);
    if current_bounding_set.is_err() {
        println!("error reading the current bounding set ");
        return;
    }
    let current_bounding_set = current_bounding_set.unwrap();

    match &new_caps.bounding {
        None => {
            println!("no bounding string in the config.json ");
        }
        Some(new_bounding) => {
            let new_bounding_caps = LinuxCapabilities::to_linux_cap(&new_bounding); //todo
            for current_bounding_cap in current_bounding_set {
                println!(
                    "checking if current thread has cap {} ",
                    current_bounding_cap
                );
                let contains = new_bounding_caps.contains(&current_bounding_cap);
                if !contains {
                    //drop it from the current bounding set since its not in the new bouding set
                    println!(
                        "the cap {} is not present in new bounding set ",
                        current_bounding_cap
                    );
                    //drop it
                    let drop_res = caps::drop(None, caps::CapSet::Bounding, current_bounding_cap);
                    match drop_res {
                        Ok(_) => {
                            println!(
                                " succeeded in dropping the cap {} from the current bounding set ",
                                current_bounding_cap
                            )
                        }
                        Err(err) => {
                            println!("unable to drop the cap {}, error {:?} from the the bounding set of the process ", current_bounding_cap, err );
                        }
                    }
                }
            }
        }
    }

    //4. //do stuff
    //     -PR_SET_KEEPCAPS
    //     -setresgid
    //     -setresuid
    let res = caps::securebits::set_keepcaps(true);
    if res.is_err() {
        println!(
            "error while setting PR_SET_KEEPCAPS, error is {:?}",
            res.err().unwrap()
        );
        return;
    }

    //5. cap_set_flag - set for CAP_EFFECTIVE, CAP_PERMITTED, CAP_INHERITABLE based on what is in the config.json file
    //fn update(&mut self, caps: &[Capability], flag: Flag, set: bool) -> bool
    //CAP_EFFECTIVE
    println!("setting effective {:?} ", new_caps.effective);
    new_caps.effective.as_ref().map(|effective| {
        let ec = LinuxCapabilities::to_linux_cap(&effective);
        println!("effective to caps , has something? {:?} ", ec);
        let res = caps::set(None, caps::CapSet::Effective, &ec);
        match res {
            Ok(_) => {
                println!(" set effective set")
            }
            Err(err) => {
                println!("error setting the effective set {:?} , error {:?}", ec, err);
                return;
            }
        }
    });

    //CAP_PERMITTED
    println!("setting permitted {:?} ", new_caps.permitted);
    new_caps.permitted.as_ref().map(|permitted| {
        let ep = LinuxCapabilities::to_linux_cap(&permitted);
        println!("permitted to caps, has something {:?}", ep);
        let res = caps::set(None, caps::CapSet::Permitted, &ep);
        match res {
            Ok(_) => {
                println!("set permitted set")
            }
            Err(err) => {
                println!("error setting the permiited set {:?} , error {:?}", ep, err);
                return;
            }
        }
    });
    //CAP_INHERITABLE
    new_caps.inheritable.as_ref().map(|inheritable| {
        let ei = LinuxCapabilities::to_linux_cap(&inheritable);
        println!("inheritable  to caps, has something {:?}", ei);
        let res = caps::set(None, caps::CapSet::Inheritable, &ei);
        match res {
            Ok(_) => {
                println!("set inheritable set")
            }
            Err(err) => {
                println!(
                    "error setting the inheritable set {:?} , error {:?}",
                    ei, err
                );
                return;
            }
        }
    });

    //then apply
    //println!("Applying the Working set - {}", current_caps);

    //6.clear all CAP_AMBIENT => prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    println!("clearing the ambient set ");
    let res = caps::clear(None, caps::CapSet::Ambient);
    match res {
        Ok(_) => {
            println!("managed to clear the ambient set ")
        }
        Err(err) => {
            println!("error clearing the ambient set , error {:?}", err);
            return;
        }
    }

    //7. set CAP_AMBIENT for all caps in the config.json AMBIENT category

    println!("setting the new ambient set ");
    new_caps.ambient.as_ref().map(|ambient| {
        let ea = LinuxCapabilities::to_linux_cap(&ambient);
        let res = caps::set(None, caps::CapSet::Ambient, &ea);
        match res {
            Ok(_) => {
                println!("succeeded  setting the ambient ");
            }
            Err(err) => {
                println!("error setting the ambient set , error {:?} ", err);
                return;
            }
        }
    });

    //no_new_privs
}
