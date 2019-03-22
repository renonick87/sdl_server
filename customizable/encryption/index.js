// skeleton functions for customized encryption

const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
let key = Buffer.alloc(32);
let iv = Buffer.alloc(16);
const password = '1324-policies';

key = Buffer.concat([Buffer.from(password)], key.length);

iv = Buffer.from(Array.prototype.map.call(iv, function(){ return 213; }))

// synchronous function for encrypting a policy table.
// encryption only affects responses to Core, not to UI Policy Table previews
exports.encryptPolicyTable = function(policy_table){
    // optionally put encryption logic here
    let policies = policy_table[0].policy_table;
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encryptedPT = cipher.update(JSON.stringify(policies), 'utf8', 'hex');
    encryptedPT += cipher.final('hex');
    return [{
        policy_table: encryptedPT
    }];
}

// synchronous function for decrypting a policy table.
exports.decryptPolicyTable = function(policy_table){
    // optionally put decryption logic here
    if(!(policy_table.app_policies && policy_table.consumer_friendly_messages && policy_table.functional_groupings
        && policy_table.module_config && policy_table.device_data && policy_table.usage_and_error_counts)){
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decryptedPT = decipher.update(policy_table, 'hex', 'utf8');
        decryptedPT += decipher.final('utf8');
        decryptedPT = JSON.parse(decryptedPT);

        if(decryptedPT.device_data == undefined){
            decryptedPT.device_data = {}
        }
        if(decryptedPT.usage_and_error_counts == undefined){
            decryptedPT.usage_and_error_counts = {}
        }
        console.log(decryptedPT)
        return decryptedPT
    }
    return policy_table
}