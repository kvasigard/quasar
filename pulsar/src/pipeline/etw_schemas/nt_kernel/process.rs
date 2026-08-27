#[allow(nonstandard_style)]
pub struct Process_TypeGroup1 {
    pub UniqueProcessKey: u32,
    pub ProcessId: u32,
    pub ParentId: u32,
    pub SessionId: u32,
    pub ExitStatus: i32,
    pub DirectoryTableBase: u32,
    pub UserSID: Vec<u8>,
    pub ImageFileName: String,
    pub CommandLine: String,
}

#[allow(nonstandard_style)]
pub struct Process_V0_TypeGroup1 {
    pub ProcessId: u32,
    pub ParentId: u32,
    pub UserSID: Vec<u8>,
    pub ImageFileName: String,
}

#[allow(nonstandard_style)]
pub struct Process_V1_TypeGroup1 {
    pub PageDirectoryBase: u32,
    pub ProcessId: u32,
    pub ParentId: u32,
    pub SessionId: u32,
    pub ExitStatus: i32,
    pub UserSID: Vec<u8>,
    pub ImageFileName: String,
}
#[allow(nonstandard_style)]
pub struct Process_V2_TypeGroup1 {
    pub UniqueProcessKey: u32,
    pub ProcessId: u32,
    pub ParentId: u32,
    pub SessionId: u32,
    pub ExitStatus: i32,
    pub DirectoryTableBase: u32,
    pub UserSID: Vec<u8>,
    pub ImageFileName: String,
    pub CommandLine: String,
}
