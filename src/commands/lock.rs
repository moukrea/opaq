// opaq: lock command implementation

use crate::error::Result;

pub fn execute() -> Result<()> {
    let keychain = crate::keychain::get_keychain();
    keychain.delete_key()?;
    Ok(())
}
