// Base definition for kernel modules. Analogue to windows/kernel_mods/kernel_mod.py

pub trait KernelModule {
    fn get_mod_name(&self) -> String;

    fn ioctl(&mut self, arch: &str, code: u32, inbuf: &[u8]) -> Result<Vec<u8>, ()> {
        unimplemented!("IOCTL not implemented for this kernel module")
    }
}
