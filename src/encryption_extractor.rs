// we create function that will extract the encryption information for each file types

pub fn excel_2007_to_2016(file_path: &str) {
    // Implementation for extracting encryption information from Excel 2007 to 2016+ files

     let path = std::path::Path::new(file_path);
    if !path.exists() {
        print!("Error: File does not exist: {}", file_path);
    }

    //we will use the zip crate to open the xlsx file as a zip archive and look for EncryptionInfo file

    /*
    example of EncryptionInfo file in xlsx file
    <encryption xmlns="http://schemas.microsoft.com/office/2006/encryption"
     xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password" 
     xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">
     <keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" 
     cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="Jp2awp27DQ8Y922oOMCZyQ=="/>
     <dataIntegrity encryptedHmacKey="LIPPqFrHxdo/y9iPjpKuotsOoCQTLYDeGN6jZJuaqTgH7Pg/h156Jg4FXpZsSdjIkUg3T8v/d18MuzKkhucM+A==" encryptedHmacValue="mGIpn+I0WC3EDDU37KFVJjtVfGv3UB9Y5QBAoUxMS3HtWUsIcnYKvaq3pnsrAnDiGcJ3si8PU6IrXy4lxUA0ig=="/>
     <keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
     <p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="6so0s2WeMyWygQoZAKMjQA==" encryptedVerifierHashInput="iLY40Lr79rXbPGy4xbgl6Q==" encryptedVerifierHashValue="y0gPGThy+IkBwI+BsbIKRIOQsqSYkifpn3uKi5j+n9xCzyZNHKK7/2htfD2M5EELyUIutSroRHMysqO6jyN9yw==" encryptedKeyValue="ITQcyJ61CZAsn1vIBULhMEmY2tL+Z/hLniTWZPF+mik="/
     ></keyEncryptor></keyEncryptors>
     </encryption>
     */

    // hashcat need hash as following format for Excel 2007 to 2016+ files
    // $office$*version*salt*encryptedVerifierHashInput*encryptedVerifierHashValue
    // 



}